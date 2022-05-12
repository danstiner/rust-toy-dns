use crate::resolver::{ResolveError, Resolver};
use crate::{protocol::*, resolver::Response};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tracing::{info, trace, warn};

pub struct Server<R>(Arc<Inner<R>>);

impl<R> Server<R>
where
    R: Resolver + Send + Sync + 'static,
{
    pub fn new(socket: UdpSocket, resolver: R) -> Server<R> {
        Server(Arc::new(Inner { socket, resolver }))
    }

    pub async fn run(&self) -> io::Result<()> {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        loop {
            let (size, origin) = self.0.socket.recv_from(&mut buf).await?;
            let bytes = &buf[0..size];

            match Packet::from_bytes(bytes) {
                Ok(packet) => self.handle_request(packet, origin),
                Err(err) => info!(?err, "Error parsing packet"),
            }
        }
    }

    fn handle_request(&self, packet: Packet, origin: SocketAddr) {
        trace!(?packet, ?origin, "Received query packet");

        let inner = Arc::clone(&self.0);

        tokio::spawn(async move {
            inner.handle_request(packet, origin).await;
        });
    }
}

struct Inner<R> {
    socket: UdpSocket,
    resolver: R,
}

impl<R> Inner<R>
where
    R: Resolver,
{
    async fn handle_request(self: &Arc<Self>, request: Packet, origin: SocketAddr) {
        let id = request.id();

        let questions = request.questions();

        assert_eq!(questions.len(), 1);

        let question = &questions[0];

        info!(
            "Query {} {:?} from {}",
            question.domain,
            question.qtype,
            origin.ip()
        );

        // TODO support ANY
        assert_eq!(question.qclass, QuestionClass::IN);

        match self.resolver.query(question.clone()).await {
            Ok(response) => {
                self.send_response(response, id, question.clone(), origin)
                    .await
            }
            Err(ResolveError::Dropped) => (),
            Err(ResolveError::Io(err)) => {
                warn!(?err, "Error resolving query");
            }
        }
    }
    async fn send_response(
        self: &Arc<Self>,
        response: Response,
        id: ID,
        question: Question,
        origin: SocketAddr,
    ) {
        let mut packet = Packet::new();
        packet.set_id(id);
        packet.set_response_code(response.code);
        packet.add_question(question);
        for answer in response.answers {
            info!(
                "Answer {} {} {:?} from {:?}",
                answer.name(),
                answer.ttl(),
                answer.rtype(),
                response.origin,
            );
            packet.add_answer(answer);
        }
        for r in response.authority {
            info!(
                "Authority {} {} {:?} from {:?}",
                r.name(),
                r.ttl(),
                r.rtype(),
                response.origin,
            );
            packet.add_authority(r);
        }
        for r in response.additional {
            info!(
                "Additional {} {} {:?} from {:?}",
                r.name(),
                r.ttl(),
                r.rtype(),
                response.origin,
            );
            packet.add_additional(r);
        }

        let bytes = packet.to_bytes().unwrap();
        trace!(?packet, ?origin, ?bytes, "Send response");
        self.socket.send_to(&bytes, origin).await.unwrap();
    }
}

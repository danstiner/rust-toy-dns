use crate::resolver::Resolver;
use crate::{protocol::*, resolver::Response};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, time::timeout};
use tracing::{info, trace};

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

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
    async fn handle_request(self: Arc<Self>, request: Packet, origin: SocketAddr) {
        let question = {
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

            question
        };

        let query = self.resolver.query(question.clone());
        let query = timeout(QUERY_TIMEOUT, query);
        let response: Response = query.await.unwrap().unwrap();

        let mut packet = Packet::new();
        packet.set_id(request.id());
        packet.set_response_code(response.code);
        packet.add_question(question.clone());
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

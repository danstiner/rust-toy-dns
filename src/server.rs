use crate::protocol::*;
use crate::resolver::Resolver;
use std::{io, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};
use tracing::{info, trace};

pub struct Server<R> {
    socket: UdpSocket,
    pub resolver: R, // Hack
}

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

impl<R: Resolver> Server<R> {
    pub fn new(socket: UdpSocket, resolver: R) -> Server<R> {
        Server { socket, resolver }
    }

    pub async fn run2(&self) -> io::Result<()> {
        let mut buf = [0u8; 512];
        loop {
            let (size, origin) = self.socket.recv_from(&mut buf).await?;
            let bytes = &buf[0..size];

            // https://datatracker.ietf.org/doc/html/rfc1035#section-7.3
            // The first step in processing arriving response datagrams is to parse the
            // response.  This procedure should include:
            //
            //    - Check the header for reasonableness.  Discard datagrams which
            //      are queries when responses are expected.
            //
            //    - Parse the sections of the message, and insure that all RRs are
            //      correctly formatted.
            //
            //    - As an optional step, check the TTLs of arriving data looking
            //      for RRs with excessively long TTLs.  If a RR has an
            //      excessively long TTL, say greater than 1 week, either discard
            //      the whole response, or limit all TTLs in the response to 1
            //      week.
            let packet = Packet::from_bytes(bytes)?;

            trace!(?packet, ?origin, ?bytes, "Received query packet");

            self.process_request(packet, origin).await?;
        }
    }
    async fn process_request(&self, request: Packet, origin: SocketAddr) -> io::Result<()> {
        assert_eq!(request.query_response(), false);

        let questions = request.questions();

        assert_eq!(questions.len(), 1);

        let question = &questions[0];

        info!(
            "Query {} {:?} from {}",
            question.name,
            question.qtype,
            origin.ip()
        );

        let query = self
            .resolver
            .query(&question.name, question.qtype, question.qclass);
        let answers = timeout(QUERY_TIMEOUT, query).await??;

        let mut response = Packet::new();
        response.set_id(request.id());
        response.add_question(&question.name, question.qtype, question.qclass);
        for answer in answers {
            info!(
                "Answer {} {} {:?} for {}",
                answer.name(),
                answer.ttl(),
                answer.rtype(),
                origin.ip()
            );
            response.add_answer(answer);
        }

        self.send_response(&response, origin).await?;

        Ok(())
    }

    async fn send_response(&self, packet: &Packet, target: SocketAddr) -> io::Result<()> {
        let bytes = packet.to_bytes()?;
        trace!(?packet, ?target, ?bytes, "Send response");
        self.socket.send_to(&bytes, target).await?;
        Ok(())
    }
}

use crate::{protocol::*, resolver::*};
use async_trait::async_trait;
use rand::prelude::*;
use std::net::SocketAddr;
use std::{io, net::ToSocketAddrs};
use tokio::net::UdpSocket;
use tracing::trace;

pub struct StubResolver<P> {
    factory: P,
}

impl StubResolver<UdpConnectionFactory> {
    pub fn new<A: ToSocketAddrs>(target: A) -> io::Result<StubResolver<UdpConnectionFactory>> {
        let target = target.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no addresses to send data to")
        })?;

        Ok(StubResolver {
            factory: UdpConnectionFactory { target },
        })
    }
}

impl<P> StubResolver<P>
where
    P: ConnectionFactory,
    <P as ConnectionFactory>::C: Connection,
{
    async fn send_query(&self, packet: &Packet, socket: &P::C) -> io::Result<()> {
        let bytes = packet.to_bytes()?;
        trace!(?packet, ?bytes, "Sending query");
        socket.send(&bytes).await?;
        Ok(())
    }

    pub async fn receive_response(
        &self,
        socket: &P::C,
        request_id: ID,
        question: Question,
    ) -> Result<Response, ResolveError> {
        // https://datatracker.ietf.org/doc/html/rfc1035#section-7.3
        // The next step is to match the response to a current resolver request.
        // The recommended strategy is to do a preliminary matching using the ID
        // field in the domain header, and then to verify that the question section
        // corresponds to the information currently desired.  This requires that
        // the transmission algorithm devote several bits of the domain ID field to
        // a request identifier of some sort.  This step has several fine points:
        //
        //    - Some name servers send their responses from different
        //      addresses than the one used to receive the query.  That is, a
        //      resolver cannot rely that a response will come from the same
        //      address which it sent the corresponding query to.  This name
        //      server bug is typically encountered in UNIX systems.
        //
        //    - If the resolver retransmits a particular request to a name
        //      server it should be able to use a response from any of the
        //      transmissions.  However, if it is using the response to sample
        //      the round trip time to access the name server, it must be able
        //      to determine which transmission matches the response (and keep
        //      transmission times for each outgoing message), or only
        //      calculate round trip times based on initial transmissions.
        //
        //    - A name server will occasionally not have a current copy of a
        //      zone which it should have according to some NS RRs.  The
        //      resolver should simply remove the name server from the current
        //      SLIST, and continue.

        // The resolver always starts with a list of server names to query (SLIST).
        // This list will be all NS RRs which correspond to the nearest ancestor
        // zone that the resolver knows about.  To avoid startup problems, the
        // resolver should have a set of default servers which it will ask should
        // it have no current NS RRs which are appropriate.  The resolver then adds
        // to SLIST all of the known addresses for the name servers, and may start
        // parallel requests to acquire the addresses of the servers when the
        // resolver has the name, but no addresses, for the name servers.

        let mut buf = [0u8; MAX_PACKET_SIZE];
        loop {
            let (size, origin) = socket.recv_from(&mut buf).await?;
            let bytes = &buf[0..size];

            let packet = Packet::from_bytes(bytes)?;

            trace!(?packet, ?bytes, ?origin, "Received response packet");

            if packet.id() == request_id {
                // Handle refusals that do not return our question. this happens for "wpad" queries.
                // TODO is that valid DNS behavior? Should these be cached?
                if packet.response_code() == ResponseCode::Refused && packet.questions().is_empty()
                {
                    return Ok(Response {
                        code: ResponseCode::Refused,
                        answer: vec![],
                        authority: vec![],
                        additional: vec![],
                        origin: Some(origin),
                    });
                }

                let response_question = {
                    let questions = packet.questions();

                    assert_eq!(questions.len(), 1);

                    questions[0].clone()
                };

                // TODO log non-matches
                if response_question == question {
                    // Received the expected response, stop listening
                    return Ok(Response {
                        code: packet.response_code(),
                        answer: packet.answers().to_vec(),
                        authority: packet.authority().to_vec(),
                        additional: packet.additional().to_vec(),
                        origin: Some(origin),
                    });
                }
            }
        }
    }
}

#[async_trait]
impl<P> Resolver for StubResolver<P>
where
    P: ConnectionFactory + Send + Sync,
    <P as ConnectionFactory>::C: Connection + Send + Sync,
{
    async fn query(&self, question: Question) -> Result<Response, ResolveError> {
        let socket = self.factory.make_connection().await?;

        // Generate an id for this request
        let request_id = socket.gen_request_id();

        // Build request
        let mut request = Packet::new();
        request.set_id(request_id);
        request.add_question(question.clone());
        request.set_recursion_desired(true);

        // Send request
        self.send_query(&request, &socket).await?;

        // Wait for response
        self.receive_response(&socket, request_id, question).await
    }
}

#[async_trait]
pub trait Connection {
    fn gen_request_id(&self) -> ID;
    async fn send(&self, buf: &[u8]) -> io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

#[async_trait]
pub trait ConnectionFactory {
    type C;

    async fn make_connection(&self) -> io::Result<Self::C>;
}

#[async_trait]
impl Connection for UdpSocket {
    #[inline]
    fn gen_request_id(&self) -> ID {
        rand::thread_rng().gen()
    }

    #[inline]
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf).await
    }

    #[inline]
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }
}

pub struct UdpConnectionFactory {
    target: SocketAddr,
}

#[async_trait]
impl ConnectionFactory for UdpConnectionFactory {
    type C = UdpSocket;

    async fn make_connection(&self) -> io::Result<Self::C> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.target).await?;
        Ok(socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[derive(Debug, Clone)]
    struct MockConnection {
        request_id: ID,
        receive_addr: SocketAddr,
        receive_data: Vec<u8>,
        sends: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    #[async_trait]
    impl Connection for MockConnection {
        fn gen_request_id(&self) -> ID {
            self.request_id
        }

        async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            self.sends.lock().push(buf.to_vec());
            Ok(buf.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let len = self.receive_data.len();
            assert!(len <= buf.len());
            buf[0..len].copy_from_slice(&self.receive_data[..]);
            Ok((len, self.receive_addr))
        }
    }

    struct MockProvider(MockConnection);

    #[async_trait]
    impl ConnectionFactory for MockProvider {
        type C = MockConnection;

        async fn make_connection(&self) -> io::Result<Self::C> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn query() {
        let remote_addr = "8.8.8.8:53".to_socket_addrs().unwrap().next().unwrap();
        // Captured response from running `dig +noedns google.com`
        let response_data: [u8; 124] = [
            0x9a, 0x9e, // ID
            0x81, 0x80, // flags = qr rd ra
            0x00, 0x01, // qdcount
            0x00, 0x06, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question 1
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // Label "google"
            0x03, 0x63, 0x6f, 0x6d, // Label "com"
            0x00, // Label end
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
            // Answer record 1
            0xc0, 0x0c, // NAME, pointer to offset 12, "google.com"
            0x00, 0x01, // TYPE
            0x00, 0x01, // CLASS
            0x00, 0x00, 0x00, 0x99, // TTL=153
            0x00, 0x04, // rdlength=4
            0x4a, 0x7d, 0x8e, 0x71, // rdata=74.125.142.113
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x99, 0x00, 0x04, 0x4a, 0x7d,
            0x8e, 0x8b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x99, 0x00, 0x04,
            0x4a, 0x7d, 0x8e, 0x64, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x99,
            0x00, 0x04, 0x4a, 0x7d, 0x8e, 0x65, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x99, 0x00, 0x04, 0x4a, 0x7d, 0x8e, 0x66, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x99, 0x00, 0x04, 0x4a, 0x7d, 0x8e, 0x8a,
        ];
        let sends = Arc::new(Mutex::new(vec![]));
        let connection = MockConnection {
            request_id: 0x9a9e,
            receive_addr: remote_addr,
            receive_data: response_data.to_vec(),
            sends: Arc::clone(&sends),
        };
        let stub = StubResolver {
            factory: MockProvider(connection),
        };

        let response = stub.lookup_ip4("google.com").await.unwrap();

        assert_eq!(
            sends.lock().to_vec(),
            // Captured request from running `dig +noedns google.com`
            vec![vec![
                0x9a, 0x9e, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
                0x03, 0x63, 0x6f, 0x6d, 0, 0, 1, 0, 1
            ]]
        );
        assert_eq!(response.origin.unwrap(), remote_addr);
        assert_eq!(
            response.answer,
            vec![
                Record::A {
                    name: String::from("google.com"),
                    class: 1,
                    ttl: 153,
                    address: "74.125.142.113".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    class: 1,
                    ttl: 153,
                    address: "74.125.142.139".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    class: 1,
                    ttl: 153,
                    address: "74.125.142.100".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    class: 1,
                    ttl: 153,
                    address: "74.125.142.101".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    class: 1,
                    ttl: 153,
                    address: "74.125.142.102".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    class: 1,
                    ttl: 153,
                    address: "74.125.142.138".parse().unwrap(),
                }
            ]
        );
    }

    // TODO test receiving unrelated packets, packets more than 512 bytes, etc
}

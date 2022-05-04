use crate::{
    protocol::{Packet, Question, QuestionClass, QuestionType, ResponseCode, ID},
    resolver::Resolver,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use rand::prelude::*;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use std::{io, net::ToSocketAddrs};
use tokio::{net::UdpSocket, sync::oneshot};
use tracing::trace;

use super::Response;

pub struct StubResolver {
    db: Arc<Mutex<Db>>,
    target: SocketAddr,
}

#[derive(Eq, Hash, PartialEq)]
struct QueryKey {
    request_id: ID,
    question: Question,
}

// TODO clear out old expired entries
struct Db {
    outstanding_queries: HashMap<QueryKey, Vec<oneshot::Sender<Response>>>,
}

impl Db {
    fn new() -> Db {
        Db {
            outstanding_queries: HashMap::new(),
        }
    }

    fn add_query(&mut self, request_id: ID, question: Question) -> oneshot::Receiver<Response> {
        let key = QueryKey {
            request_id,
            question,
        };

        // Setup a channel to return the response on
        let (sender, receiver) = oneshot::channel();

        self.outstanding_queries
            .entry(key)
            .or_insert_with(|| Vec::new())
            .push(sender);

        receiver
    }
}

impl StubResolver {
    pub fn new<A: ToSocketAddrs>(target: A) -> io::Result<StubResolver> {
        let target = target.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no addresses to send data to")
        })?;

        Ok(StubResolver {
            db: Arc::new(Mutex::new(Db::new())),
            target,
        })
    }

    async fn query_remote(&self, packet: &Packet) -> io::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        self.send_query(packet, &socket).await?;
        self.receive_response(&socket).await?;
        Ok(())
    }

    async fn send_query(&self, packet: &Packet, socket: &UdpSocket) -> io::Result<()> {
        let bytes = packet.to_bytes()?;
        trace!(?packet, ?bytes, ?self.target, "Sending query");
        socket.send_to(&bytes, self.target).await?;
        Ok(())
    }

    pub async fn receive_response(&self, socket: &UdpSocket) -> io::Result<()> {
        socket.connect(self.target).await?;

        let mut buf = [0u8; 512];
        loop {
            let (size, origin) = socket.recv_from(&mut buf).await?;
            let bytes = &buf[0..size];

            let packet = Packet::from_bytes(bytes)?;

            trace!(?packet, ?bytes, ?origin, "Received response packet");

            if self.handle_response(packet, origin).await? {
                // Received the expected response, stop listening
                return Ok(());
            }
        }
    }

    async fn handle_response(&self, packet: Packet, origin: SocketAddr) -> io::Result<bool> {
        assert!(packet.query_response());
        assert_eq!(packet.response_code(), ResponseCode::NoErrorCondition);

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

        let question = {
            let questions = packet.questions();

            assert_eq!(questions.len(), 1);

            questions[0].clone()
        };

        let mut db = self.db.lock();

        let entry = db.outstanding_queries.remove_entry(&QueryKey {
            request_id: packet.id(),
            question,
        });

        if let Some((_key, response_channels)) = entry {
            for channel in response_channels {
                channel
                    .send(Response {
                        answers: packet.answers().to_vec(),
                        origin,
                    })
                    .unwrap();
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[async_trait]
impl Resolver for Arc<StubResolver> {
    async fn query(
        &self,
        domain: &str,
        qtype: QuestionType,
        qclass: QuestionClass,
    ) -> io::Result<Response> {
        // Generate an id for this request
        let request_id: ID = rand::thread_rng().gen();

        // Record as an outstanding query
        let receiver = {
            let question = Question {
                name: domain.to_owned(),
                qtype,
                qclass,
            };

            self.db.lock().add_query(request_id, question)
        };

        // Send request packet
        let mut request = Packet::new();
        request.set_id(request_id);
        request.add_question(domain, qtype, qclass);
        request.set_recursion_desired(true);
        self.query_remote(&request).await?;

        Ok(receiver.await.unwrap())
    }
}

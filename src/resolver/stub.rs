use crate::{
    protocol::{Packet, QuestionClass, QuestionType, Record, ResponseCode, ID},
    resolver::Resolver,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use rand::prelude::*;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use std::{io, net::ToSocketAddrs};
use tokio::{net::UdpSocket, sync::oneshot};
use tracing::{info, trace};

pub struct ForwardingResolver {
    db: Arc<Mutex<Db>>,
    socket: UdpSocket,
    target: SocketAddr,
}

struct OutstandingQuery {
    domain: String,
    qtype: QuestionType,
    qclass: QuestionClass,
    response_channel: tokio::sync::oneshot::Sender<Packet>,
}

struct Db {
    outstanding_queries: HashMap<ID, Vec<OutstandingQuery>>,
}

impl Db {
    fn new() -> Db {
        Db {
            outstanding_queries: HashMap::new(),
        }
    }
}

impl ForwardingResolver {
    pub fn new<A: ToSocketAddrs>(socket: UdpSocket, target: A) -> io::Result<ForwardingResolver> {
        let target = target.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no addresses to send data to")
        })?;

        Ok(ForwardingResolver {
            db: Arc::new(Mutex::new(Db::new())),
            socket,
            target,
        })
    }

    async fn send_query(&self, packet: &Packet) -> io::Result<()> {
        let bytes = packet.to_bytes()?;
        trace!(?packet, ?bytes,  ?self.target,"Sending query");
        self.socket.send_to(&bytes, self.target).await?;
        Ok(())
    }

    pub async fn run(&self) -> io::Result<()> {
        let mut buf = [0u8; 512];
        loop {
            let (size, origin) = self.socket.recv_from(&mut buf).await?;
            let bytes = &buf[0..size];

            let packet = Packet::from_bytes(bytes)?;

            trace!(?packet, ?bytes, ?origin, "Received response packet");

            self.process_response(packet, origin).await?;
        }
    }

    async fn process_response(&self, response: Packet, origin: SocketAddr) -> io::Result<()> {
        assert!(response.query_response());
        assert_eq!(response.response_code(), ResponseCode::NoErrorCondition);

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

        // TODO some amount of verification of the origin address

        let mut db = self.db.lock();

        if let Some(outstanding_queries) = db.outstanding_queries.get_mut(&response.id()) {
            let outstanding = outstanding_queries.pop().unwrap();

            outstanding.response_channel.send(response).unwrap();

            // TODO loop to find and extract matching outstanding queries
            // for outstanding in outstanding_queries.iter() {
            //     // else log that we've ignored this unsolicited response
            // }
            // Clear matching queries from oustanding set, we've answered them
            // TODO remove entry if ID's entry is entirely empty now
        }

        Ok(())
    }
}

#[async_trait]
impl Resolver for ForwardingResolver {
    async fn query(
        &self,
        domain: &str,
        qtype: QuestionType,
        qclass: QuestionClass,
    ) -> io::Result<Vec<Record>> {
        // Generate an id for this request
        let request_id: ID = {
            let mut rng = rand::thread_rng();
            rng.gen()
        };

        // Record as an outstanding query
        let receiver = {
            let mut db = self.db.lock();

            let (sender, receiver) = oneshot::channel::<Packet>();

            db.outstanding_queries
                .entry(request_id)
                .or_insert_with(|| Vec::new())
                .push(OutstandingQuery {
                    domain: domain.to_owned(),
                    qtype,
                    qclass,
                    response_channel: sender,
                });

            receiver
        };

        // Send request packet
        let mut request = Packet::new();
        request.set_id(request_id);
        request.add_question(domain, qtype, qclass);
        request.set_recursion_desired(true);
        self.send_query(&request).await?;

        // Wait for response
        let response = receiver.await.unwrap();
        Ok(response.answers().to_vec())
    }
}

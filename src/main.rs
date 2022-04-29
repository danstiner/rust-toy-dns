mod protocol;

use parking_lot::Mutex;
use rand::prelude::*;
use std::{
    collections::HashMap,
    env,
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};
use tokio::net::UdpSocket;
use tracing::{info, trace};

use crate::protocol::*;

struct QueryEntry {
    origin_address: SocketAddr,
    origin_id: ID,
}

struct Db {
    outstanding_queries: HashMap<ID, Vec<QueryEntry>>,
}

impl Db {
    fn new() -> Db {
        Db {
            outstanding_queries: HashMap::new(),
        }
    }
}

struct Server {
    db: Arc<Mutex<Db>>,
    listen_socket: UdpSocket,
    upstream_socket: UdpSocket,
    upstream_address: SocketAddr,
}

impl Server {
    fn new(listen_socket: UdpSocket, upstream_socket: UdpSocket) -> Server {
        Server {
            db: Arc::new(Mutex::new(Db::new())),
            listen_socket,
            upstream_socket,
            upstream_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
        }
    }
    async fn run(self) -> io::Result<()> {
        tokio::try_join!(self.listen_loop(), self.upstream_loop())?;
        Ok(())
    }

    async fn listen_loop(&self) -> io::Result<()> {
        let mut buf = [0u8; 512];
        loop {
            let (size, origin) = self.listen_socket.recv_from(&mut buf).await?;
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

    async fn upstream_loop(&self) -> io::Result<()> {
        let mut buf = [0u8; 512];
        loop {
            let (size, origin) = self.upstream_socket.recv_from(&mut buf).await?;
            let bytes = &buf[0..size];

            let packet = Packet::from_bytes(bytes)?;

            trace!(?packet, ?origin, ?bytes, "Received response packet");

            self.process_response(packet, origin).await?;
        }
    }

    async fn process_response(&self, response: Packet, origin: SocketAddr) -> io::Result<()> {
        assert!(response.query_response());

        for answer in response.answers() {
            info!(
                "Answer {} {} {:?} from {}",
                answer.name(),
                answer.ttl(),
                answer.rtype(),
                origin.ip()
            );
        }

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
            for query in outstanding_queries.iter() {
                // Check question sections match, use first matching
                let mut response = response.clone();
                response.set_id(query.origin_id);
                self.send_response(&response, query.origin_address).await?;

                // else log that we've ignored this unsolicited response
            }
            // Clear matching queries from oustanding set, we've answered them
            outstanding_queries.clear();
            // TODO remove entry if ID's entry is entirely empty now
        }

        Ok(())
    }

    async fn process_request(&self, request: Packet, origin: SocketAddr) -> io::Result<()> {
        assert!(!request.query_response());

        let questions = request.questions();

        assert_eq!(questions.len(), 1);

        let question = &questions[0];

        info!(
            "Query {} {:?} from {}",
            question.name,
            question.qtype,
            origin.ip()
        );

        // TODO a proper implementation
        let mut rng = rand::thread_rng();
        let upstream_id: ID = rng.gen();
        let mut upstream_request = request.clone();
        upstream_request.set_id(upstream_id);

        // TODO First check for existing requests
        {
            let mut db = self.db.lock();

            db.outstanding_queries
                .entry(upstream_id)
                .or_insert_with(|| Vec::new())
                .push(QueryEntry {
                    origin_address: origin,
                    origin_id: request.id(),
                });
        }

        self.send_query(&upstream_request, self.upstream_address)
            .await?;

        Ok(())
    }

    async fn send_query(&self, packet: &Packet, target: SocketAddr) -> io::Result<()> {
        let bytes = packet.to_bytes()?;
        trace!(?packet, ?target, ?bytes, "Send query");
        self.upstream_socket.send_to(&bytes, target).await?;
        Ok(())
    }

    async fn send_response(&self, packet: &Packet, target: SocketAddr) -> io::Result<()> {
        let bytes = packet.to_bytes()?;
        trace!(?packet, ?target, ?bytes, "Send response");
        self.listen_socket.send_to(&bytes, target).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();

    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let listen_socket = UdpSocket::bind(&listen_addr).await?;
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;

    let server = Server::new(listen_socket, upstream_socket);

    server.run().await?;

    Ok(())
}

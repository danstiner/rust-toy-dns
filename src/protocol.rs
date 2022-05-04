use byteorder::{NetworkEndian, ReadBytesExt};
use bytes::BufMut;
use enum_primitive_derive::Primitive;
use modular_bitfield::{bitfield, prelude::*};
use num_traits::{FromPrimitive, ToPrimitive};
use std::{
    io::{self, Cursor, Read},
    net::Ipv4Addr,
};
use tracing::trace;

pub const MAX_PACKET_SIZE: usize = 512;

pub type ID = u16;

/*
https://datatracker.ietf.org/doc/html/rfc1035#section-3.1

3.1. Name space definitions

<domain-name> is a domain name represented as a series of labels, and
terminated by a label with zero length.  <character-string> is a single
length octet followed by that number of characters.  <character-string>
is treated as binary information, and can be up to 256 characters in
length (including the length octet).

In order to reduce the size of messages, the domain system utilizes a
compression scheme which eliminates the repetition of domain names in a
message.  In this scheme, an entire domain name or a list of labels at
the end of a domain name is replaced with a pointer to a prior occurance
of the same name.

The pointer takes the form of a two octet sequence:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|                OFFSET                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The first two bits are ones.  This allows a pointer to be distinguished
from a label, since the label must begin with two zero bits because
labels are restricted to 63 octets or less.  (The 10 and 01 combinations
are reserved for future use.)  The OFFSET field specifies an offset from
the start of the message (i.e., the first octet of the ID field in the
domain header).  A zero offset specifies the first byte of the ID field,
etc.

The compression scheme allows a domain name in a message to be
represented as either:

   - a sequence of labels ending in a zero octet

   - a pointer

   - a sequence of labels ending with a pointer

Pointers can only be used for occurances of a domain name where the
format is not class specific.  If this were not the case, a name server
or resolver would be required to know the format of all RRs it handled.
As yet, there are no such cases, but they may occur in future RDATA
formats.

If a domain name is contained in a part of the message subject to a
length field (such as the RDATA section of an RR), and compression is
used, the length of the compressed name is used in the length
calculation, rather than the length of the expanded name.

Programs are free to avoid using pointers in messages they generate,
although this will reduce datagram capacity, and may cause truncation.
However all programs are required to understand arriving messages that
contain pointers.

Each label is represented as a one octet length field followed by that
number of octets. Since every domain name ends with the null label of
the root, a domain name is terminated by a length byte of zero.  The
high order two bits of every length octet must be zero, and the
remaining six bits of the length field limit the label to 63 octets or
less.
 */
#[derive(Debug, PartialEq)]
struct CompressedDomain {
    labels: Vec<String>,
    pointer: Option<u16>,
}

impl CompressedDomain {
    pub fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<CompressedDomain> {
        let mut domain = CompressedDomain {
            labels: Vec::new(),
            pointer: Option::None,
        };
        let mut total_len = 0usize;

        loop {
            let octet = cursor.read_u8()?;
            total_len += 1;

            // Upper two bits of first octect are used as a type tag
            match octet & 0b1100_0000 {
                0b1100_0000 => {
                    // 14 bit offset pointer to a label somewhere else in the message.
                    // Consists of lower six bits of the octect plus the following octect
                    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    // | 1  1|                OFFSET                   |
                    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    let upper_byte = octet & 0b0011_1111;
                    let lower_byte = cursor.read_u8()?;
                    let offset = (upper_byte as u16) << 8 | lower_byte as u16;

                    domain.pointer = Some(offset);
                    return Ok(domain);
                }
                0b1000_0000 => todo!("invalid label"),
                0b0100_0000 => todo!("invalid label"),
                0b0000_0000 => {
                    // Label where first octect is the label's length
                    let len = octet.into();

                    if len == 0 {
                        return Ok(domain);
                    }

                    total_len += len;

                    if total_len > 255 {
                        todo!("Total label length is too long")
                    }

                    let pointed = CompressedDomain::read_label_content(cursor, len)?;

                    domain.labels.push(String::from(pointed));
                }
                _ => unreachable!(),
            }
        }
    }

    pub fn uncompress(&self, cursor: &Cursor<&[u8]>) -> io::Result<String> {
        let domain = self.labels.join(".");

        if let Some(offset) = self.pointer {
            let mut cursor = cursor.clone();
            cursor.set_position(offset.into());

            // TODO prevent recursion
            let compressed = CompressedDomain::read_from(&mut cursor)?;
            let uncompressed = compressed.uncompress(&cursor)?;
            if domain.is_empty() {
                Ok(uncompressed)
            } else {
                Ok(format!("{domain}.{uncompressed}"))
            }
        } else {
            Ok(domain)
        }
    }

    fn read_label_content(cursor: &mut Cursor<&[u8]>, len: usize) -> io::Result<String> {
        // labels are restricted to 63 octets or less
        debug_assert!(len <= 63);

        let mut buf = [0u8; 63];
        cursor.read_exact(&mut buf[0..len])?;
        let bytes = &buf[0..len];

        Ok(String::from(std::str::from_utf8(bytes).unwrap()))
    }
}

fn write_name<B: BufMut>(name: &str, buf: &mut B) {
    // todo assert!(!name.is_empty());

    if !name.is_empty() {
        for label in name.split(".") {
            let bytes = label.as_bytes();

            assert!(!bytes.is_empty());
            assert!(bytes.len() <= 63);

            buf.put_u8(bytes.len() as u8);
            buf.put_slice(bytes);
        }
    }

    buf.put_u8(0);
}

/*

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
*/
#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
}

impl Packet {
    pub fn new() -> Packet {
        Packet {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }

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
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Packet> {
        let mut cursor = Cursor::new(bytes);

        let header = Header::read_from(&mut cursor)?;

        // TODO We only support parsing questions and anwsers so far
        assert!(header.authority_count == 0);
        assert!(header.additional_count == 0);

        let questions = (0..header.question_count)
            .map(|_| Question::read_from(&mut cursor))
            .collect::<io::Result<Vec<Question>>>()?;

        let answers = (0..header.answer_count)
            .map(|_| Record::read_from(&mut cursor))
            .collect::<io::Result<Vec<Record>>>()?;

        Ok(Packet {
            header,
            questions,
            answers,
        })
    }

    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![];
        self.header.write_to(&mut buf)?;
        for question in &self.questions {
            question.write_to(&mut buf)?;
        }
        for answer in &self.answers {
            answer.write_to(&mut buf)?;
        }
        Ok(buf)
    }

    pub fn id(&self) -> ID {
        self.header.id
    }

    pub fn set_id(&mut self, id: ID) {
        self.header.id = id;
    }

    pub fn query_response(&self) -> bool {
        self.header.query_response
    }

    pub fn response_code(&self) -> ResponseCode {
        self.header.response_code
    }

    pub fn authoritative_answer(&self) -> bool {
        self.header.authoritative_answer
    }

    pub fn truncated_message(&self) -> bool {
        self.header.truncated_message
    }

    pub fn recursion_desired(&self) -> bool {
        self.header.recursion_desired
    }

    pub fn recursion_available(&self) -> bool {
        self.header.recursion_available
    }

    pub fn set_recursion_desired(&mut self, value: bool) {
        self.header.recursion_desired = value;
    }

    pub fn questions(&self) -> &[Question] {
        &self.questions
    }

    pub fn add_question(&mut self, question: Question) {
        self.header.question_count += 1;
        self.questions.push(question);
    }

    pub fn answers(&self) -> &[Record] {
        &self.answers
    }

    pub fn add_answer(&mut self, answer: Record) {
        self.header.answer_count += 1;
        self.answers.push(answer);
    }
}

#[derive(BitfieldSpecifier)]
#[bits = 4]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ResponseCode {
    NoErrorCondition = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

/* Header section

                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    // Packet identifier assigned by the program generating any kind of query.
    // This identifier is copied the corresponding reply and can be used by the
    // requester to match up replies to outstanding queries.
    id: ID,

    // Query Response
    query_response: bool,

    // OPCODE - four bit field that specifies kind of query in this message. This value is set by
    // the originator of a query and copied into the response.
    operation_code: OpCode,

    // Authoritative Answer
    authoritative_answer: bool,

    // TC - TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
    truncated_message: bool,

    // RD - this bit may be set in a query and is copied into the response.  If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional
    recursion_desired: bool,

    // Recursion Available
    recursion_available: bool,

    // Three bit field reserved for future use. Must be zero in all queries and responses.
    z: u8,

    // RCODE - 4 bit field is set as part of responses
    response_code: ResponseCode,

    // Question Count
    question_count: u16,

    // Answer Count
    answer_count: u16,

    // NSCOUNT - number of name server resource records in the authority records section
    authority_count: u16,

    // ARCOUNT - number of resource records in the additional records section
    additional_count: u16,
}

#[bitfield(bits = 16)]
#[repr(u16)]
#[derive(Debug)]
struct HeaderFlags {
    #[bits = 4]
    rcode: ResponseCode,
    z: B3,
    ra: bool,
    rd: bool,
    tc: bool,
    aa: bool,
    #[bits = 4]
    opcode: OpCode,
    qr: bool,
}

impl Header {
    pub fn new() -> Header {
        Header {
            id: 0,
            query_response: false,
            operation_code: OpCode::Query,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,
            recursion_available: false,
            z: 0,
            response_code: ResponseCode::NoErrorCondition,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Header> {
        let id = cursor.read_u16::<NetworkEndian>()?;
        let flags = cursor.read_u16::<NetworkEndian>()?;
        let qdcount = cursor.read_u16::<NetworkEndian>()?;
        let ancount = cursor.read_u16::<NetworkEndian>()?;
        let nscount = cursor.read_u16::<NetworkEndian>()?;
        let arcount = cursor.read_u16::<NetworkEndian>()?;

        let flags = HeaderFlags::from(flags);

        trace!(
            id,
            ?flags,
            qdcount,
            ancount,
            nscount,
            arcount,
            "Header::read_from"
        );

        Ok(Header {
            id,
            query_response: flags.qr(),
            operation_code: flags.opcode(),
            authoritative_answer: flags.aa(),
            truncated_message: flags.tc(),
            recursion_desired: flags.rd(),
            recursion_available: flags.ra(),
            z: flags.z(),
            response_code: flags.rcode(),
            question_count: qdcount,
            answer_count: ancount,
            authority_count: nscount,
            additional_count: arcount,
        })
    }

    pub fn write_to<B: BufMut>(&self, buf: &mut B) -> io::Result<()> {
        let flags = HeaderFlags::new()
            .with_qr(self.query_response)
            .with_opcode(self.operation_code)
            .with_aa(self.authoritative_answer)
            .with_tc(self.truncated_message)
            .with_rd(self.recursion_desired)
            .with_ra(self.recursion_available)
            .with_z(self.z)
            .with_rcode(self.response_code);

        // todo assert_eq!(0, flags.z(), "Reserved field must be zero");

        buf.put_u16(self.id);
        buf.put_u16(flags.into());
        buf.put_u16(self.question_count);
        buf.put_u16(self.answer_count);
        buf.put_u16(self.authority_count);
        buf.put_u16(self.additional_count);
        Ok(())
    }
}

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
#[derive(BitfieldSpecifier)]
#[bits = 4]
#[derive(Copy, Clone, Debug, Primitive, PartialEq, Eq)]
pub enum OpCode {
    Query = 0,        // a standard query (QUERY)
    InverseQuery = 1, // an inverse query (IQUERY)
    Status = 2,       // a server status request (STATUS)
                      // 3-15 reserved for future use
}

// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
#[derive(Copy, Clone, Debug, Primitive, PartialEq, Eq, Hash)]
pub enum QuestionType {
    A = 1,      // host address
    NS = 2,     // authoritative name server
    MD = 3,     // mail destination (Obsolete - use MX)
    MF = 4,     // mail forwarder (Obsolete - use MX)
    CNAME = 5,  // the canonical name for an alias
    SOA = 6,    // marks the start of a zone of authority
    MB = 7,     // mailbox domain name (EXPERIMENTAL)
    MG = 8,     // mail group member (EXPERIMENTAL)
    MR = 9,     // mail rename domain name (EXPERIMENTAL)
    NULL = 10,  // null RR (EXPERIMENTAL)
    WKS = 11,   // well known service description
    PTR = 12,   // domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15,    // mail exchange
    TXT = 16,   // text strings

    AAAA = 28,

    AXFR = 252,  // request for a transfer of an entire zone
    MAILB = 253, // request for mailbox-related records (MB, MG or MR)
    MAILA = 254, // request for mail agent RRs (Obsolete - see MX)
    ALL = 255,   // aka "*", request for all records
}

// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
#[derive(Copy, Clone, Debug, Primitive, PartialEq, Eq, Hash)]
pub enum QuestionClass {
    UNKNOWN0 = 0,
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
}

/* Question section

                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    pub domain: String,
    pub qtype: QuestionType,
    pub qclass: QuestionClass,
}

impl Question {
    pub fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Question> {
        /* qname
        a domain name represented as a sequence of labels, where
        each label consists of a length octet followed by that
        number of octets.  The domain name terminates with the
        zero length octet for the null label of the root.  Note
        that this field may be an odd number of octets; no
        padding is used. */
        let domain = CompressedDomain::read_from(cursor)?;
        let qtype = cursor.read_u16::<NetworkEndian>()?;
        let qclass = cursor.read_u16::<NetworkEndian>()?;

        let name = domain.uncompress(&cursor)?;
        let qtype = QuestionType::from_u16(qtype)
            .ok_or(io::Error::new(io::ErrorKind::Other, "Invalid type"))?;
        let qclass = QuestionClass::from_u16(qclass)
            .ok_or(io::Error::new(io::ErrorKind::Other, "Invalid type"))?;

        Ok(Question {
            domain: name,
            qtype,
            qclass,
        })
    }

    pub fn write_to<B: BufMut>(&self, buf: &mut B) -> io::Result<()> {
        let qtype = self.qtype.to_u16().unwrap();
        let qclass = self.qclass.to_u16().unwrap();

        // TODO compress name
        write_name(&self.domain, buf);
        buf.put_u16(qtype);
        buf.put_u16(qclass);
        Ok(())
    }
}

/*
The answer, authority, and additional sections all share the same
format: a variable number of resource records, where the number of
records is specified in the corresponding count field in the header.
Each resource record has the following format:
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#[derive(Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub enum Record {
    // https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.1
    A {
        name: String,
        ttl: u32,
        address: Ipv4Addr,
    },
    NS {
        name: String,
        ttl: u32,
        authoritative_host: String,
    },
    CNAME {
        name: String,
        ttl: u32,
        cname: String,
    },
}

impl Record {
    pub fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Record> {
        let name = CompressedDomain::read_from(cursor)?;
        let rtype = cursor.read_u16::<NetworkEndian>()?;
        let class = cursor.read_u16::<NetworkEndian>()?;
        let ttl = cursor.read_u32::<NetworkEndian>()?;
        let rdlength = cursor.read_u16::<NetworkEndian>()?.into();

        assert!(class == 1);

        let mut buffer = [0u8; 10];
        cursor.read_exact(&mut buffer[0..rdlength])?;
        let bytes = &buffer[0..rdlength];

        let name = name.uncompress(&cursor)?;
        let rtype = QuestionType::from_u16(rtype)
            .ok_or(io::Error::new(io::ErrorKind::Other, "Invalid type"))?;

        // TODO check type is valid for RDATA, not all qtypes are

        match rtype {
            QuestionType::A => Record::parse_a(name, ttl, bytes),
            QuestionType::CNAME => Record::parse_cname(name, ttl, bytes),
            _ => todo!(),
        }
    }

    pub fn write_to<B: BufMut>(&self, buf: &mut B) -> io::Result<()> {
        match self {
            Record::A { name, ttl, address } => {
                let rtype = QuestionType::A;
                let class = 1u16; // TODO
                let rdata = address.octets();

                Record::write_with_rdata(buf, name, rtype, class, *ttl, &rdata[..])
            }
            _ => todo!(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Record::A { name, .. } => name,
            _ => todo!(),
        }
    }

    pub fn rtype(&self) -> QuestionType {
        match self {
            Record::A { .. } => QuestionType::A,
            _ => todo!(),
        }
    }

    pub fn ttl(&self) -> u32 {
        match self {
            Record::A { ttl, .. } => *ttl,
            _ => todo!(),
        }
    }

    fn parse_a(name: String, ttl: u32, bytes: &[u8]) -> io::Result<Record> {
        assert_eq!(bytes.len(), 4);
        let address = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        Ok(Record::A { name, ttl, address })
    }

    fn parse_cname(name: String, ttl: u32, bytes: &[u8]) -> io::Result<Record> {
        let cname = String::from(std::str::from_utf8(bytes).unwrap());
        Ok(Record::CNAME { name, ttl, cname })
    }

    fn write_with_rdata<B: BufMut>(
        buf: &mut B,
        name: &str,
        rtype: QuestionType,
        class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> io::Result<()> {
        let rtype = rtype.to_u16().unwrap();
        let rdlength = rdata.len().try_into().unwrap();

        // TODO compress name
        write_name(name, buf);

        buf.put_u16(rtype);
        buf.put_u16(class);
        buf.put_u32(ttl);
        buf.put_u16(rdlength);
        buf.put_slice(&rdata[..]);

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_domain_read_from_labels() {
        // F.ISI.ARPA
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           1           |           F           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           3           |           I           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           S           |           I           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           4           |           A           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           R           |           P           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           A           |           0           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let domain_bytes = [
            1, 'F' as u8, 3, 'I' as u8, 'S' as u8, 'I' as u8, 4, 'A' as u8, 'R' as u8, 'P' as u8,
            'A' as u8, 0,
        ];
        let mut cursor = Cursor::new(&domain_bytes[..]);

        let domain = CompressedDomain::read_from(&mut cursor).unwrap();

        assert_eq!(
            cursor.position() as usize,
            domain_bytes.len(),
            "Expect all bytes to be read"
        );
        assert_eq!(
            domain,
            CompressedDomain {
                labels: vec!["F".to_string(), "ISI".to_string(), "ARPA".to_string()],
                pointer: None,
            }
        );
        assert_eq!("F.ISI.ARPA", domain.uncompress(&cursor).unwrap());
    }

    // TODO is this a valid name
    #[test]
    fn test_domain_read_empty_labels() {
        // +--+--+--+--+--+--+--+--+
        // |           0           |
        // +--+--+--+--+--+--+--+--+
        let domain_bytes = [0];
        let mut cursor = Cursor::new(&domain_bytes[..]);

        let domain = CompressedDomain::read_from(&mut cursor).unwrap();

        assert_eq!(
            cursor.position() as usize,
            domain_bytes.len(),
            "Expect all bytes to be read"
        );
        assert_eq!(
            domain,
            CompressedDomain {
                labels: vec![],
                pointer: None,
            }
        );
        assert_eq!("", domain.uncompress(&cursor).unwrap());
    }
    #[test]
    fn test_domain_read_from_pointer() {
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 1  1|                26                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let domain_bytes = [0b11000000, 20];
        let mut cursor = Cursor::new(&domain_bytes[..]);

        let domain = CompressedDomain::read_from(&mut cursor).unwrap();

        assert_eq!(
            cursor.position() as usize,
            domain_bytes.len(),
            "Expect all bytes to be read"
        );
        assert_eq!(
            domain,
            CompressedDomain {
                labels: vec![],
                pointer: Some(20),
            }
        );
    }

    #[test]
    fn test_domain_read_from_labels_and_pointer() {
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           3           |           F           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           O           |           O           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 1  1|                20                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let domain_bytes = [3, 'F' as u8, 'O' as u8, 'O' as u8, 0b11000000, 20];
        let mut cursor = Cursor::new(&domain_bytes[..]);

        let domain = CompressedDomain::read_from(&mut cursor).unwrap();

        assert_eq!(
            cursor.position() as usize,
            domain_bytes.len(),
            "Expect all bytes to be read"
        );
        assert_eq!(
            domain,
            CompressedDomain {
                labels: vec!["FOO".to_string()],
                pointer: Some(20),
            }
        );
    }

    // TODO add tests for domain name uncompress

    #[test]
    fn test_domain_write_f_isi_arpa() {
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           1           |           F           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           3           |           I           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           S           |           I           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           4           |           A           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           R           |           P           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           A           |           0           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let expected_bytes = [
            1, 'F' as u8, 3, 'I' as u8, 'S' as u8, 'I' as u8, 4, 'A' as u8, 'R' as u8, 'P' as u8,
            'A' as u8, 0,
        ];
        let mut buf = Vec::new();

        write_name("F.ISI.ARPA", &mut buf);

        assert_eq!(expected_bytes, &buf[..]);
    }

    #[test]
    fn test_domain_write_google_com() {
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           6           |           g           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           o           |           o           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           g           |           l           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           e           |           3           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           c           |           o           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |           m           |           0           |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let expected_bytes = [
            6, 'g' as u8, 'o' as u8, 'o' as u8, 'g' as u8, 'l' as u8, 'e' as u8, 3, 'c' as u8,
            'o' as u8, 'm' as u8, 0,
        ];
        let mut buf = Vec::new();

        write_name("google.com", &mut buf);

        assert_eq!(expected_bytes, &buf[..]);
    }

    #[test]
    fn test_packet_from_query_a_bytes() {
        // Captured query from running `dig +noedns google.com`
        const QUERY_GOOGLE_COM: [u8; 28] = [
            0x0f, 0x13, // ID
            0x01, 0x20, // flags = rd, z = 2
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
            0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let packet = Packet::from_bytes(&QUERY_GOOGLE_COM[..]).unwrap();

        assert_eq!(
            packet.questions,
            vec![Question {
                domain: String::from("google.com"),
                qtype: QuestionType::A,
                qclass: QuestionClass::IN,
            }]
        );
    }

    #[test]
    fn test_header_write_to_with_request() {
        let header = Header {
            id: 6666,
            query_response: false,
            operation_code: OpCode::Query,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: false,
            z: 2,
            response_code: ResponseCode::NoErrorCondition,
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        };
        let mut buf = Vec::new();

        header.write_to(&mut buf).unwrap();

        assert_eq!(
            [0x1a, 0x0a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &buf[..]
        )
    }

    #[test]
    fn test_header_write_to_with_failure_response() {
        let header = Header {
            id: 9001,
            query_response: true,
            operation_code: OpCode::Query,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: true,
            z: 2,
            response_code: ResponseCode::ServerFailure,
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        };
        let mut buf = Vec::new();

        header.write_to(&mut buf).unwrap();

        assert_eq!(
            [0x23, 0x29, 0x81, 0xa2, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &buf[..]
        )
    }

    #[test]
    fn test_packet_from_response_a_bytes() {
        // Captured response from running `dig +noedns google.com`
        const RESPONSE_GOOGLE_COM: [u8; 124] = [
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
            0x00, 0x01, // QTYPE
            0x00, 0x01, // QCLASS
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

        let packet = Packet::from_bytes(&RESPONSE_GOOGLE_COM[..]).unwrap();

        assert_eq!(true, packet.query_response());
        assert_eq!(false, packet.authoritative_answer());
        assert_eq!(false, packet.truncated_message());
        assert_eq!(true, packet.recursion_desired());
        assert_eq!(true, packet.recursion_available());

        assert_eq!(
            packet.questions,
            vec![Question {
                domain: String::from("google.com"),
                qtype: QuestionType::A,
                qclass: QuestionClass::IN,
            }]
        );

        assert_eq!(
            packet.answers,
            vec![
                Record::A {
                    name: String::from("google.com"),
                    ttl: 153,
                    address: "74.125.142.113".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    ttl: 153,
                    address: "74.125.142.139".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    ttl: 153,
                    address: "74.125.142.100".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    ttl: 153,
                    address: "74.125.142.101".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    ttl: 153,
                    address: "74.125.142.102".parse().unwrap(),
                },
                Record::A {
                    name: String::from("google.com"),
                    ttl: 153,
                    address: "74.125.142.138".parse().unwrap(),
                }
            ]
        );
    }
}

#[cfg(test)]
mod properties {

    use itertools::Itertools;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use std::cmp;

    use super::*;

    fn gen_range(g: &mut Gen, start: usize, end: usize) -> usize {
        if start == end {
            return start;
        }
        assert!(end > start);
        let range_size = end - start;

        // Note, this is not truely uniform, but the bias is small for small ranges
        start + (usize::arbitrary(g) % range_size)
    }

    fn gen_range_u16(g: &mut Gen, start: u16, end: u16) -> u16 {
        gen_range(g, start.into(), end.into()).try_into().unwrap()
    }

    fn arbitrary_label(g: &mut Gen, max_len: usize) -> String {
        assert!(max_len >= 1);

        // Randomly choose a valid label length less than gen size and given max len
        let max_len = cmp::min(max_len, 63);
        let max_len = cmp::min(max_len, g.size());
        let max_len = gen_range(g, 1, max_len);

        let mut label = String::with_capacity(max_len);

        loop {
            assert!(label.len() <= max_len);
            if label.len() == max_len {
                return label;
            }
            let ch = char::arbitrary(g);
            if ch == '.' {
                continue;
            }
            if label.len() + ch.len_utf8() > max_len {
                // Characters are variable length in utf8, try again to gen a shorter one
                continue;
            }
            label.push(ch);
        }
    }

    fn arbitrary_name(g: &mut Gen) -> String {
        // Randomly choose a name length to target, cannot be longer than 255 bytes
        let max_name_len = cmp::min(255, g.size());
        let max_name_len = gen_range(g, 1, max_name_len);

        // Generate labels up to length limit
        let mut name: Vec<String> = Vec::new();

        loop {
            let name_len: i32 = name.iter().map(|l| l.len() as i32 + 1).sum();
            let max_label_len = max_name_len as i32 - name_len - 2;
            if max_label_len < 1 {
                break;
            }
            let label = arbitrary_label(g, max_label_len as usize);
            name.push(label);
        }

        name.join(".")
    }

    impl Arbitrary for OpCode {
        fn arbitrary(g: &mut Gen) -> OpCode {
            match gen_range(g, 0, 3) {
                0 => OpCode::Query,
                1 => OpCode::InverseQuery,
                2 => OpCode::Status,
                _ => unreachable!(),
            }
        }
    }

    impl Arbitrary for QuestionType {
        fn arbitrary(g: &mut Gen) -> QuestionType {
            match gen_range(g, 1, 1) {
                1 => QuestionType::A, // TODO other question types
                _ => unreachable!(),
            }
        }
    }

    impl Arbitrary for QuestionClass {
        fn arbitrary(g: &mut Gen) -> Self {
            match gen_range_u16(g, 1, 5) {
                1 => QuestionClass::IN,
                2 => QuestionClass::CS,
                3 => QuestionClass::CH,
                4 => QuestionClass::HS,
                _ => unreachable!(),
            }
        }
    }

    impl Arbitrary for ResponseCode {
        fn arbitrary(g: &mut Gen) -> ResponseCode {
            match gen_range(g, 0, 6) {
                0 => ResponseCode::NoErrorCondition,
                1 => ResponseCode::FormatError,
                2 => ResponseCode::ServerFailure,
                3 => ResponseCode::NameError,
                4 => ResponseCode::NotImplemented,
                5 => ResponseCode::Refused,
                _ => unreachable!(),
            }
        }
    }

    impl Arbitrary for Packet {
        fn arbitrary(g: &mut Gen) -> Packet {
            let header = Header::arbitrary(g);
            let questions = (0..header.question_count)
                .map(|_| Question::arbitrary(g))
                .collect_vec();
            let answers = (0..header.answer_count)
                .map(|_| Record::arbitrary(g))
                .collect_vec();
            Packet {
                header,
                questions,
                answers,
            }
        }
    }

    impl Arbitrary for Header {
        fn arbitrary(g: &mut Gen) -> Header {
            Header {
                id: u16::arbitrary(g),
                query_response: bool::arbitrary(g),
                operation_code: OpCode::Query, // TODO generate random values
                authoritative_answer: bool::arbitrary(g),
                truncated_message: bool::arbitrary(g),
                recursion_desired: bool::arbitrary(g),
                recursion_available: bool::arbitrary(g),
                z: 0,
                response_code: ResponseCode::NoErrorCondition,
                question_count: gen_range_u16(g, 0, 2),
                answer_count: gen_range_u16(g, 0, 6),
                authority_count: 0,
                additional_count: 0,
            }
        }
    }

    impl Arbitrary for Question {
        fn arbitrary(g: &mut Gen) -> Question {
            Question {
                domain: arbitrary_name(g),
                qtype: QuestionType::arbitrary(g),
                qclass: QuestionClass::arbitrary(g),
            }
        }
    }

    impl Arbitrary for Record {
        fn arbitrary(g: &mut Gen) -> Record {
            // TODO other record types
            Record::A {
                name: arbitrary_name(g),
                ttl: u32::arbitrary(g),
                address: Ipv4Addr::arbitrary(g),
            }
        }
    }

    #[quickcheck]
    fn write_then_read_header_is_identity(h: Header) {
        let mut buf = vec![];
        h.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf[..]);

        assert_eq!(h, Header::read_from(&mut cursor).unwrap());
    }

    #[quickcheck]
    fn write_then_read_question_is_identity(q: Question) {
        let mut buf = vec![];
        q.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf[..]);

        assert_eq!(q, Question::read_from(&mut cursor).unwrap());
    }

    #[quickcheck]
    fn write_then_read_record_is_identity(r: Record) {
        let mut buf = vec![];
        r.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf[..]);

        assert_eq!(r, Record::read_from(&mut cursor).unwrap());
    }

    #[quickcheck]
    fn write_then_read_packet_is_identity(p: Packet) {
        let bytes = p.to_bytes().unwrap();

        assert_eq!(p, Packet::from_bytes(&bytes[..]).unwrap());
    }
}

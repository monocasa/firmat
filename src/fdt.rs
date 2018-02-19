use nom::IResult;
use nom::be_u32;
use nom::be_u64;

pub const HEADER_MAGIC: [u8;4] = [0xd0, 0x0d, 0xfe, 0xed];
pub const VERSION: u32 = 17;
pub const LAST_COMP_VERSION: u32 = 16;

#[derive(Debug,PartialEq,Eq,Copy,Clone)]
pub struct Header {
    pub magic: [u8;4],
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

pub fn parse_header(i: &[u8]) -> IResult<&[u8], Header> {
    do_parse!(i,
        tag!(&HEADER_MAGIC)       >>
        totalsize:         be_u32 >>
        off_dt_struct:     be_u32 >>
        off_dt_strings:    be_u32 >>
        off_mem_rsvmap:    be_u32 >>
        version:           be_u32 >>
        last_comp_version: be_u32 >>
        boot_cpuid_phys:   be_u32 >>
        size_dt_strings:   be_u32 >>
        size_dt_struct:    be_u32 >>

        (Header {
            magic:             HEADER_MAGIC,
            totalsize:         totalsize,
            off_dt_struct:     off_dt_struct,
            off_dt_strings:    off_dt_strings,
            off_mem_rsvmap:    off_mem_rsvmap,
            version:           version,
            last_comp_version: last_comp_version,
            boot_cpuid_phys:   boot_cpuid_phys,
            size_dt_strings:   size_dt_strings,
            size_dt_struct:    size_dt_struct,
        })
    )
}

fn residue_to_align(unaligned: usize) -> usize {
    (4 - (unaligned % 4)) % 4
}

#[derive(Debug,PartialEq,Eq,Copy,Clone)]
pub enum Token<'a> {
    BeginNode{name: &'a [u8]},
    EndNode,
    Prop{len: u32, nameoff: u32, value: &'a [u8]},
    Nop,
    End,
}

fn parse_token_begin_node(i: &[u8]) -> IResult<&[u8], Token> {
    do_parse!(i,
        name: take_until_and_consume!("\x00") >>
        take!(residue_to_align(name.len() + 1))  >> 

        (Token::BeginNode {
            name: name,
        })
    )
}

fn parse_token_end_node(i: &[u8]) -> IResult<&[u8], Token> {
    Ok((i, Token::EndNode))
}

fn parse_token_prop(i: &[u8]) -> IResult<&[u8], Token> {
    do_parse!(i,
        len: be_u32 >>
        nameoff: be_u32 >>
        value: take!(len) >>
        take!(residue_to_align(len as usize)) >>

        (Token::Prop {
            len: len,
            nameoff: nameoff,
            value: value,
        })
    )
}

fn parse_token_nop(i: &[u8]) -> IResult<&[u8], Token> {
    Ok((i, Token::Nop))
}

fn parse_token_end(i: &[u8]) -> IResult<&[u8], Token> {
    Ok((i, Token::End))
}

pub fn parse_token(i: &[u8]) -> IResult<&[u8], Token> {
    switch!(i, be_u32,
        0x0000_0001 => call!(parse_token_begin_node) |
        0x0000_0002 => call!(parse_token_end_node) |
        0x0000_0003 => call!(parse_token_prop) |
        0x0000_0004 => call!(parse_token_nop) |
        0x0000_0009 => call!(parse_token_end)
    )
}

#[derive(Debug,PartialEq,Eq,Copy,Clone)]
pub struct ReserveEntry {
    pub address: u64,
    pub size: u64,
}

pub fn parse_reserve_entry(i: &[u8]) -> IResult<&[u8], ReserveEntry> {
    do_parse!(i,
        address: be_u64 >>
        size:    be_u64 >>

        (ReserveEntry {
            address: address,
            size: size,
        })
    )
}

pub struct ReserveEntryIterator<'a> {
    slice: &'a [u8],
}

impl<'a> ReserveEntryIterator<'a> {
    fn new(fdt: &'a Fdt<'a>) -> ReserveEntryIterator<'a> {
        let base = fdt.header.off_mem_rsvmap as usize;
        ReserveEntryIterator {
            slice: &fdt.mem[base..],
        }
    }
}

impl<'a> Iterator for ReserveEntryIterator<'a> {
    type Item = ReserveEntry;

    fn next(&mut self) -> Option<ReserveEntry> {
        match parse_reserve_entry(self.slice) {
            Ok((remainder, entry)) => {
                if (entry.address == 0) && (entry.size == 0) {
                    //We intentionally don't ratchet up the slice here so that
                    //  subsequent calls continue to return None
                    return None;
                }

                self.slice = remainder;
                Some(entry)
            },
            _ => None,
        }
    }
}

pub struct TokenIterator<'a> {
    slice: &'a [u8],
}

impl<'a> TokenIterator<'a> {
    fn new(fdt: &'a Fdt<'a>) -> TokenIterator<'a> {
        let base = fdt.header.off_dt_struct as usize;
        let end = base + (fdt.header.size_dt_struct as usize);
        TokenIterator {
            slice: &fdt.mem[base..end],
        }
    }
}

impl<'a> Iterator for TokenIterator<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        // Not strictly required as this will be covered by IResult::Incomplete,
        //    but I don't really like going down exceptional pathways in the
        //    the normal code flow
        if self.slice.is_empty() {
            return None;
        }

        match parse_token(self.slice) {
            Ok((remainder, token)) => {
                self.slice = remainder;
                Some(token)
            },
            _ => None
        }
    }
}

#[derive(Debug,PartialEq,Eq)]
pub enum FdtParseError {
    TotalsizeLargerThanMem,
}

#[derive(Debug,PartialEq,Eq)]
pub enum StringMarshalError {
    ValidationError(::std::str::Utf8Error),
    OutOfRange,
}

impl From<::std::str::Utf8Error> for StringMarshalError {
    fn from(error: ::std::str::Utf8Error) -> StringMarshalError {
        StringMarshalError::ValidationError(error)
    }
}

pub struct Fdt<'a> {
    header: Header,
    mem: &'a [u8],
}

impl<'a> Fdt<'a> {
    pub fn new(header: &Header, mem: &'a [u8]) -> Result<Fdt<'a>, FdtParseError> {
        if (header.totalsize as usize) < mem.len() {
            return Err(FdtParseError::TotalsizeLargerThanMem);
        }

        Ok(Fdt {
            header: header.clone(),
            mem: mem,
        })
    }

    pub fn mem_rsvmap_iter(&self) -> ReserveEntryIterator {
        ReserveEntryIterator::new(self)
    }

    pub fn token_iter(&self) -> TokenIterator {
        TokenIterator::new(self)
    }

    fn str_region_slice(&self) -> &'a [u8] {
        let base = self.header.off_dt_strings as usize;
        let end = base + self.header.size_dt_strings as usize;

        &self.mem[base..end]
    }

    pub fn str_from_off(&self, nameoff: u32) -> Result<&'a str, StringMarshalError> {
        let region = self.str_region_slice();

        let base = nameoff as usize;
        let mut end = base;

        loop {
            if end >= region.len() {
                return Err(StringMarshalError::OutOfRange);
            }

            if region[end] == ('\0' as u8) {
                break;
            }

            end += 1;
        }

        match ::std::str::from_utf8(&region[base..end]) {
            Ok(marshalled_string) => Ok(marshalled_string),
            Err(err) => Err(StringMarshalError::ValidationError(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_header;
    use super::parse_token;
    use super::Header;
    use super::Token;

    use nom::ErrorKind;
    use nom::IResult;

    const EMPTY: &'static [u8] = b"";

    #[test]
    fn parse_header_good() {
        let test_header_bytes: [u8;40] = [
            0xd0,0x0d,0xfe,0xed, 0x00,0x01,0x00,0x00,
            0x00,0x00,0x00,0x40, 0x00,0x00,0x1b,0xdc,
            0x00,0x00,0x00,0x30, 0x00,0x00,0x00,0x11,
            0x00,0x00,0x00,0x10, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x01,0xa1, 0x00,0x00,0x1b,0x9c,
        ];

        assert_eq!(parse_header(&test_header_bytes), 
            IResult::Done(EMPTY, Header {
                magic:             super::HEADER_MAGIC,
                totalsize:         0x0001_0000,
                off_dt_struct:     0x0000_0040,
                off_dt_strings:    0x0000_1bdc,
                off_mem_rsvmap:    0x0000_0030,
                version:           super::VERSION,
                last_comp_version: super::LAST_COMP_VERSION,
                boot_cpuid_phys:   0x0000_0000,
                size_dt_strings:   0x0000_01a1,
                size_dt_struct:    0x0000_1b9c,
            }));
    }

    #[test]
    fn parse_header_bad_magic() {
        let test_header_bytes: [u8;4] = [
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

        assert_eq!(parse_header(&test_header_bytes),
            IResult::Error(ErrorKind::Tag));
    }

    #[test]
    fn parse_token_begin_node_full_str() {
        let test_token: [u8;12] = [
            0x00, 0x00, 0x00, 0x01,
            //t     e     s     t     i     n     g    \0
            0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x00,
        ];

        assert_eq!(parse_token(&test_token),
            IResult::Done(EMPTY, Token::BeginNode{name: b"testing"})
        );
    }

    #[test]
    fn parse_token_begin_node_partially_str() {
        let test_token: [u8;12] = [
            0x00, 0x00, 0x00, 0x01,
            //h     e     l     l     o    \0
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00,
        ];

        assert_eq!(parse_token(&test_token),
            IResult::Done(EMPTY, Token::BeginNode{name: b"hello"})
        );
    }

    #[test]
    fn parse_token_end_node_good() {
        let test_token: [u8; 4] = [
            0x00, 0x00, 0x00, 0x02,
        ];

        assert_eq!(parse_token(&test_token),
            IResult::Done(EMPTY, Token::EndNode)
        );
    }

    #[test]
    fn parse_token_prop_full_value() {
        let test_token: [u8; 16] = [
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x04,
            0x12, 0x34, 0x56, 0x78,
            0xaa, 0xbb, 0xcc, 0xdd,
        ];

        assert_eq!(parse_token(&test_token),
            IResult::Done(EMPTY, Token::Prop{
                len: 4,
                nameoff: 0x12345678,
                value: b"\xaa\xbb\xcc\xdd",
            })
        );
    }

    #[test]
    fn parse_token_prop_partially_value() {
        let test_token: [u8; 16] = [
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x02,
            0xaa, 0xbb, 0xcc, 0xdd,
            0x32, 0x18, 0x00, 0x00,
        ];

        assert_eq!(parse_token(&test_token),
            IResult::Done(EMPTY, Token::Prop{
                len: 2,
                nameoff: 0xaabbccdd,
                value: b"\x32\x18",
            })
        );
    }

    #[test]
    fn parse_token_nop_good() {
        let test_token: [u8; 4] = [
            0x00, 0x00, 0x00, 0x04,
        ];

        assert_eq!(parse_token(&test_token),
            IResult::Done(EMPTY, Token::Nop)
        );
    }

    #[test]
    fn parse_token_end_good() {
        let test_token: [u8; 4] = [
            0x00, 0x00, 0x00, 0x09,
        ];

        assert_eq!(parse_token(&test_token),
            IResult::Done(EMPTY, Token::End)
        );
    }
}

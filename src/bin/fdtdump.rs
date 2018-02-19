extern crate firmat;

use std::fs::File;
use std::io::Read;

use firmat::fdt;

pub const DTS_VER_STRING: &str = "/dts-v1/;";

fn indent(times: u32) {
    for _ in 0..times {
        print!("    ");
    }
}

fn isprint(character: u8) -> bool {
    (character > 0x1F) && (character < 0x7f)
}

const NULL_CHAR: u8 = '\0' as u8;

fn is_printable_string(slice: &[u8]) -> bool {
    if slice.is_empty() {
        return false;
    }

    if slice[slice.len()-1] != NULL_CHAR {
        return false;
    }

    let mut prev = 1u8;
    for c in slice.iter() {
        if isprint(*c) {
            prev = *c;
            continue;
        }

        if *c == NULL_CHAR {
            if prev == NULL_CHAR {
                return false;
            }
        } else {
            return false;
        }

        prev = *c;
    }

    true
}

fn strlen(slice: &[u8]) -> usize {
    let mut len = 0;

    for c in slice {
        if *c == ('\0' as u8) {
            return len;
        }

        len += 1;
    }

    len
}

fn print_prop_data(slice: &[u8]) {
    if slice.len() == 0 {
        return;
    }

    if is_printable_string(slice) {
        print!(" = ");
        let mut base: usize = 0;
        loop {
            let subslice = &slice[base..];
            let len = strlen(subslice);

            // unwrap is ok as we previously verified that this slice only 
            //   consists of printable characters and '\0'
            let substr = std::str::from_utf8(&subslice[..len]).unwrap();

            print!("\"{}\"", substr);

            if (len + base + 1) >= slice.len() {
                break;
            }

            print!(", ");

            base += len + 1;
        }
    } else if (slice.len() % 4) == 0 {
        print!(" = <");
        let mut base: usize = 0;
        while base < slice.len() {
            print!("0x{:02x}{:02x}{:02x}{:02x}",
                    slice[base+0], slice[base+1],
                    slice[base+2], slice[base+3]);

            base += 4;

            if base < slice.len() {
                print!(" ");
            }
        }
        print!(">");
    } else {
        print!(" = [");
        let mut base: usize = 0;
        while base < slice.len() {
            print!("{:02x}", slice[base]);

            base += 1;

            if base < slice.len() {
                print!(" " );
            }
        }
        print!("]");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage:  {} FDT_FILE", args[0]);
        std::process::exit(1);
    }

    let filename = args[1].clone();

    let mut file = match File::open(&filename) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("ERROR:  Unable to open {}: {}", &filename, err);
            std::process::exit(1);
        },
    };

    let mut bytes: Vec<u8> = Vec::new();

    match file.read_to_end(&mut bytes) {
        Ok(_) => {},
        Err(err) => {
            eprintln!("ERROR:  Unable to read {}: {}", &filename, err);
            std::process::exit(1);
        },
    }

    let header = match fdt::parse_header(&bytes) {
        Ok((_, header)) => header,
        Err(err) => {
            eprintln!("ERROR:  Unable to parse header: {:?}", err);
            std::process::exit(1);
        },
    };

    if (header.totalsize as usize) < bytes.len() {
        eprintln!("ERROR:  header.totalsize is less than file size");
        std::process::exit(1);
    }

    let fdt = match fdt::Fdt::new(&header, &bytes) {
        Ok(fdt) => fdt,
        Err(_) => {
            eprintln!("Unable to build FDT object");
            std::process::exit(1);
        },
    };

    println!("{}", DTS_VER_STRING);
    println!("// magic:\t\t0x{:02x}{:02x}{:02x}{:02x}",
        header.magic[0], header.magic[1],
        header.magic[2], header.magic[3]);
    println!("// totalsize:\t\t{:#x} ({})", header.totalsize, header.totalsize);
    println!("// off_dt_struct:\t{:#x}", header.off_dt_struct);
    println!("// off_dt_strings:\t{:#x}", header.off_dt_strings);
    println!("// off_mem_rsvmap:\t{:#x}", header.off_mem_rsvmap);
    println!("// version:\t\t{}", header.version);
    println!("// last_comp_version:\t{}", header.last_comp_version);
    if header.version >= 2 {
        println!("// boot_cpuid_phys:\t{:#x}", header.boot_cpuid_phys);
    }
    if header.version >= 3 {
        println!("// size_dt_strings:\t{:#x}", header.size_dt_strings);
    }
    if header.version >= 17 {
        println!("// size_dt_struct:\t{:#x}", header.size_dt_struct);
    }

    println!("");

    for range in fdt.mem_rsvmap_iter() {
        println!("/memreserve/ {:#x} {:#x};", range.address, range.size);
    }

    let mut depth = 0;
    for token in fdt.token_iter() {
        match token {
            fdt::Token::BeginNode{ref name} => {
                let mut name_str = std::str::from_utf8(name).unwrap();
                if name_str == "" {
                    name_str = "/";
                }
                indent(depth);
                println!("{} {{", name_str);
                depth += 1;
            },

            fdt::Token::Prop{len: _, nameoff, ref value} => {
                indent(depth);
                print!("{}", fdt.str_from_off(nameoff).unwrap());
                print_prop_data(value);
                println!(";");
            },

            fdt::Token::EndNode => {
                depth -= 1;
                indent(depth);
                println!("}};");
            },
            _ => { },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_printable_string;

    #[test]
    fn is_printable_string_empty() {
        assert!(!is_printable_string(b""));
    }

    #[test]
    fn is_printable_string_binary() {
        let test_bytes: [u8;4] = [0x01, 0x63, 0x36, 0x00];
        assert!(!is_printable_string(&test_bytes));
    }
}

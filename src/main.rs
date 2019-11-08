use std::io::{SeekFrom};
use std::io::prelude::*;
use std::fs;
use std::fs::File;
use std::process;
use std::error::Error;
use std::ascii;
use std::char;
use std::collections::HashMap;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use regex::bytes::Regex;

#[macro_use]
extern crate clap;
use clap::{Arg, App, ArgGroup};
use colored::*;

#[derive(Debug)]
struct Maps {
    addr : (u64,u64),
    perm : u8,
    path : String,
}

 const PROT_NONE :u8 = 0x0;
 const PROT_READ :u8 = 0x1;
 const PROT_WRITE:u8 = 0x2;
 const PROT_EXEC :u8 = 0x4;

fn parse_maps(pid: u32) -> Result<Vec<Maps>,Box<dyn Error>>{

    let contents = fs::read_to_string(format!("/proc/{}/maps",pid))?;
    let mut memory : Vec<Maps> = vec![];

    for lines in contents.lines() {
        let mut iter = lines.split_whitespace();

        // Extracting address range 
        let addr : (u64 , u64 ) = match iter.next() {
            Some(range) => {
                let addr :Vec<&str> = range.split("-").collect();
                (u64::from_str_radix(addr[0],16)?,
                 u64::from_str_radix(addr[1],16)?)
            },
            None => (0,0),
        };

        // Extracting permission 
        let perm_str = iter.next().unwrap();
        let mut perm :u8 = PROT_NONE;
        if perm_str.contains("x") { perm = perm | PROT_EXEC;}
        if perm_str.contains("r") { perm = perm | PROT_READ;}
        if perm_str.contains("w") { perm = perm | PROT_WRITE;}

        // Extracting binary path
        let path;
        path = match iter.nth(3){
            Some(p) => p.to_string(),
            None => "[unassigned]".to_string(),
        };

        // println!("{:x}-{:x} {} {}",addr.0,addr.1,perm,path);
        memory.push(Maps{addr,perm,path});
    }

    Ok(memory)
}

struct Config{
    pid :u32,
    psize :usize,
    needle :u64,
    string: bool,
    maps: bool,
    expr: Option<String>,
    perm :u8,
    search_range: (u64,u64),
    pattern:Option<String>,
}

fn parse_args() -> Result<Config, Box<dyn Error>>{
    let matches = App::new("scanmem")
                          .version("0.1")
                          .about("scan memory of running process")
                          .arg(Arg::with_name("pid")
                               .short("p")
                               .long("pid")
                               .help("Set the target process id")
                               .takes_value(true)
                               .value_name("PID")
                               .required(true))
                          .arg(Arg::with_name("bytes")
                               .short("b")
                               .long("bytes")
                               .takes_value(true)
                               .value_name("value")
                               .help("Search for 1-byte value"))
                          .arg(Arg::with_name("word")
                               .short("w")
                               .long("word")
                               .takes_value(true)
                               .value_name("value")
                               .help("Search for 2-byte value"))
                          .arg(Arg::with_name("dword")
                               .short("d")
                               .long("dword")
                               .takes_value(true)
                               .value_name("value")
                               .help("Search for 4-byte value"))
                          .arg(Arg::with_name("qword")
                               .short("q")
                               .long("qword")
                               .takes_value(true)
                               .value_name("value")
                               .help("Search for 8-byte value"))
                          .arg(Arg::with_name("string")
                               .short("s")
                               .long("string")
                               .takes_value(true)
                               .value_name("string")
                               .help("Search for string"))
                          .arg(Arg::with_name("range")
                               .short("r")
                               .long("range")
                               .multiple(true)
                               .takes_value(true)
                               .value_name("range")
                               .help("Address range to search for"))
                          .arg(Arg::with_name("perm")
                               .long("perm")
                               .takes_value(true)
                               .value_name("perm")
                               .help("Permission of memory to search for  : <rwx>"))
                            .arg(Arg::with_name("pattern")
                               .short("i")
                               .long("in")
                               .takes_value(true)
                               .value_name("pattern")
                               .help("Search inside specified region, \nunnamed regions are marked as [unassigned]"))
                            .arg(Arg::with_name("maps")
                               .short("m")
                               .long("maps")
                               .help("Print out the memory maping"))
                          .group(ArgGroup::with_name("type")
                                .required(true)
                                .args(&["bytes", "word", "dword", "qword" ,"string","maps"]))
                          .get_matches();

    let mut config = Config {
        pid : 0 ,
        psize : 0 ,
        needle :0 ,
        string: false ,
        maps: false,
        expr: None,
        pattern: None,
        perm: PROT_NONE,
        search_range : (0,0),
    };
    
    config.pid = value_t!(matches, "pid", u32)?;

    if matches.is_present("bytes"){
        config.psize = 8;
        config.needle = value_t!(matches, "bytes", u8)? as u64;
    }
    else if matches.is_present("word"){
        config.psize = 16;
        config.needle = value_t!(matches, "word", u16)? as u64;
    }
    else if matches.is_present("dword"){
        config.psize = 32;
        config.needle = value_t!(matches, "dword", u32)? as u64;
    }
    else if matches.is_present("qword"){
        config.psize = 64;
        config.needle = value_t!(matches, "qword", u64)?;
    }
    else { config.psize = 0 ; config.needle = 0;}

    if matches.is_present("string"){
        config.string = true;
        config.expr = Some(matches.value_of("string").unwrap().to_string());
    }

    if matches.is_present("range"){
        let mut values = matches.values_of("range").unwrap();
        if values.len() > 1 {
        config.search_range = (parse_int(values.next().unwrap())?,
                               parse_int(values.next().unwrap())?);
        }
    }

    if matches.is_present("pattern"){
        config.pattern = Some(matches.value_of("pattern").unwrap().to_string());
    }

    if matches.is_present("maps"){
        config.maps = true;
    }
    if matches.is_present("perm"){
        let value = matches.value_of("perm").unwrap();
        if value.contains("x") { config.perm = config.perm | PROT_EXEC;}
        if value.contains("r") { config.perm = config.perm | PROT_READ;}
        if value.contains("w") { config.perm = config.perm | PROT_WRITE;}
    }
    
    Ok(config)
}

fn parse_int(inp: &str) -> Result<u64,Box<dyn Error>>{

   let res = inp.parse().unwrap_or(
       u64::from_str_radix(&inp,16)?);
    Ok(res)
}

fn read_from_mem(pid: u32, offset:u64 , size: usize) -> Result<Vec<u8>, Box<dyn Error>> {

    let mut mem = File::open(format!("/proc/{}/mem",pid))?;
    mem.seek(SeekFrom::Start(offset))?;

    let mut buffer = vec![0;size];
    mem.read_exact(&mut buffer)?;

    Ok(buffer)
}

fn scan_pointer(maps: Maps, buffer :&[u8], size :u64, needle :u64) -> Vec<u64>{

    let mut rdr = Cursor::new(buffer);
    let mut res : Vec<u64> = Vec::new();

    let len = maps.addr.1-maps.addr.0;

    for i in 0..len/size {
        let value : u64 =
            match size {
                8 => rdr.read_u8().unwrap()   as u64,
                16 => rdr.read_u16::<LittleEndian>().unwrap() as u64,
                32 => rdr.read_u32::<LittleEndian>().unwrap() as u64,
                64 => rdr.read_u64::<LittleEndian>().unwrap() as u64,
                _  => panic!("invalid pointer size"),
            };

        if value == needle {
            let addr = maps.addr.0 + (i * size );
            res.push(addr);
        }
    }
    return res;
}

fn escape_bytes(buffer :&[u8]) -> String {
    let mut res = String::new();
    for bytes in buffer {
        for i in ascii::escape_default(*bytes){
            res.push(char::from_u32(i as u32).unwrap());
        }
    }
    return res;
}

fn scan_regex(maps: Maps,buffer :&[u8], regex :&str) -> HashMap<u64,String> {
    let regex : String = format!(r"(?-u)(?P<match>{})",regex);
    let re = Regex::new(&regex).unwrap();

    let mut res :HashMap<u64,String> = HashMap::new();
    for i in  re.captures_iter(&buffer) {
        let cap = i.name("match").unwrap();
        let addr = maps.addr.0 + cap.start() as u64;
        res.insert(addr , escape_bytes(&cap.as_bytes()));
    }
    return res;
}

fn filter_memory(memory: Vec<Maps>,search_range : (u64,u64), perm :u8, pattern : Option<String>) -> Vec<Maps>{

    let mut res :Vec<Maps> = Vec::new();
    let start = search_range.0;
    let end = search_range.1;

    for i in memory{
        // select maps based on the permission specified
        if (perm & i.perm) != 0 {
            res.push(i);
            continue;
        }
        // select maps which are in the correct address range.
        if i.addr.0 >= start && i.addr.1 <= end{
            res.push(i);
            break;
        }
        
        //Select maps according to the path pattern epecified
        pattern.as_ref().map(|s|
            if i.path.contains(s){
                res.push(i);
            });
    }
    res
}

fn print_maps(memory: &Vec<Maps>){
    for i in memory {
        println!("0x{:x}-0x{:x}\t{} {}" ,i.addr.0,
                    i.addr.1,i.perm,i.path);
    }
}

fn main() {

    let config = parse_args().unwrap_or_else(|err| {
        eprintln!("{}",err);
        process::exit(1);
    });
    
    let memory = parse_maps(config.pid).unwrap_or_else(|err| {
        eprintln!("Parsing maps: {}",err);
        process::exit(1);
    });

    if config.maps {
        print_maps(&memory);
    }
    
       
    let memory = filter_memory(memory,config.search_range,
                               config.perm,config.pattern);

    for m in memory {
        // Currently Only searching for in stack and Heap
        // have to implemet maps filter functionality
        // if m.perm & 1 == 0 {continue;}
        // if ! m.path.contains("stack") && ! m.path.contains("heap") {continue;}
        
        println!("{} {:#x}-{:#x}\t {}","Scanning memory".red(), m.addr.0,m.addr.1,m.path);

        let offset = m.addr.0;
        let size = m.addr.1 - m.addr.0;
        let buffer = read_from_mem(config.pid,offset,size as usize ).unwrap_or_else(|err|{
            eprintln!("read from mem: {}",err);
            vec![]
        });

        if config.string {
            let expr = config.expr.as_ref().unwrap();
            let res = scan_regex(m,&buffer,&expr);
            if res.len()>0 {
                for (addr, value) in res.iter(){
                    println!("{} {:20} @ {:#x}","Found".green(), value, addr);
                }
            }
        }
        else{
            let res =  scan_pointer(m,&buffer,config.psize as u64,config.needle);
            for i in res {
                println!("{} : {:#18x} @ {:#18x}","Found".green(), config.needle , i)
            }
        }
    }
}

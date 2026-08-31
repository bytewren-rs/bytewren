use bytewren_capture::capture_packet;
use std::env;
use std::io;

fn main() -> io::Result<()> {
    let ifname = env::args().nth(1).unwrap_or_else(|| "eth0".to_string());
    println!("Ожидаем пакет на {}...", ifname);

    let packet = capture_packet(&ifname)?;

    println!("Метаданные пакета: {:?}", packet.meta());

    for (i, b) in packet.buf().iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            println!();
        }
        print!("{:02x} ", b);
    }
    println!();
    Ok(())
}

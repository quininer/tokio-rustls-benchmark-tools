use std::io;
use std::time::{ Duration, Instant };
use std::fs::{ self, File };
use std::path::PathBuf;
use std::sync::Arc;
use std::net::{ ToSocketAddrs, SocketAddr };
use std::io::BufReader;
use argh::FromArgs;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::net::TcpStream;
use tokio::io::{ AsyncWriteExt, copy, sink };
use tokio_rustls::{ TlsConnector, rustls::ClientConfig, webpki::DNSNameRef };


/// Tokio Rustls benchmark tools
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, default = "443")]
    port: u16,

    /// domain
    #[argh(option)]
    domain: Option<String>,

    /// cafile
    #[argh(option)]
    cafile: Option<PathBuf>,

    /// concurrent number
    #[argh(option, default = "1")]
    concurrent: usize,

    /// input file
    #[argh(option)]
    input: Option<PathBuf>,

    /// keep test time (s)
    #[argh(option)]
    keep: Option<u64>
}


#[tokio::main]
async fn main() -> io::Result<()> {
    let options: Options = argh::from_env();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = options.domain.unwrap_or(options.host);
    let content = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\n\r\n",
        domain
    );

    let mut config = ClientConfig::new();
    if let Some(cafile) = &options.cafile {
        let mut pem = BufReader::new(File::open(cafile)?);
        config.root_store.add_pem_file(&mut pem)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
    } else {
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    }
    let connector = TlsConnector::from(Arc::new(config));

    let input = if let Some(path) = options.input {
        fs::read(path)?
    } else {
        Vec::new()
    };
    let (sender, mut queue) = mpsc::unbounded_channel();
    let keep = options.keep.map(Duration::from_secs);
    let start = Instant::now();

    let ctx = Arc::new(Context {
        connector, addr,
        input, domain, content,
        start, keep, sender
    });

    for _ in 0..options.concurrent {
        let ctx = ctx.clone();

        spawn_task(ctx);
    }

    drop(ctx);

    let mut count = 0;
    while let Some(j) = queue.recv().await {
        j.await??;
        count += 1;
    }

    let dur = start.elapsed().as_secs_f64();

    println!("result: {}/{}s", count, dur);
    println!("mean: {} per secs", (count as f64) / dur);

    Ok(())
}

struct Context {
    connector: TlsConnector,
    addr: SocketAddr,
    input: Vec<u8>,
    domain: String,
    content: String,
    start: Instant,
    keep: Option<Duration>,
    sender: mpsc::UnboundedSender<JoinHandle<io::Result<()>>>
}

fn spawn_task(ctx: Arc<Context>) {
    let sender = ctx.sender.clone();

    let join = tokio::spawn(async move {
        let stream = TcpStream::connect(&ctx.addr).await?;
        let mut output = sink();

        let domain = DNSNameRef::try_from_ascii_str(&ctx.domain)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

        let mut stream = ctx.connector.connect(domain, stream).await?;
        stream.write_all(ctx.content.as_bytes()).await?;

        stream.write_all(&*ctx.input).await?;
        stream.shutdown().await?;

        copy(&mut stream, &mut output).await?;

        // release fd
        drop(stream);

        if let Some(keep) = ctx.keep {
            if ctx.start.elapsed() <= keep {
                spawn_task(ctx);
            }
        }

        Ok(()) as io::Result<()>
    });

    let _ = sender.send(join);
}

use std::io;
use std::pin::Pin;
use std::future::Future;
use std::task::{ Context as Ctx, Poll };
use std::time::{ Duration, Instant };
use std::fs::{ self, File };
use std::path::PathBuf;
use std::sync::Arc;
use std::net::{ ToSocketAddrs, SocketAddr };
use std::io::BufReader;
use argh::FromArgs;
use tokio::time::timeout;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::net::TcpStream;
use tokio::io::{ AsyncWriteExt, split, copy, sink };
use tokio_rustls::{ TlsConnector, rustls::ClientConfig, webpki::DNSNameRef };


/// Tokio Rustls benchmark tools
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>,

    /// cafile
    #[argh(option, short = 'c')]
    cafile: Option<PathBuf>,

    /// concurrent number
    #[argh(option, short = 'n', default = "1")]
    concurrent: usize,

    /// input file
    #[argh(option, short = 'i')]
    input: Option<PathBuf>,

    /// keep test time (s)
    #[argh(option, short = 'k')]
    keep: Option<u64>,

    /// timeout (s)
    #[argh(option, short = 't')]
    timeout: Option<u64>
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
    let timeout = options.timeout.map(Duration::from_secs);
    let start = Instant::now();

    let ctx = Arc::new(Context {
        connector, addr,
        input, domain, content,
        start, keep, timeout,
        sender
    });

    for _ in 0..options.concurrent {
        let ctx = ctx.clone();

        spawn_task(ctx);
    }

    drop(ctx);

    let mut count = 0;
    let mut failed = 0;
    let mut total = Duration::from_secs(0);
    let mut handshake_total = Duration::from_secs(0);
    let mut end_total = Duration::from_secs(0);
    let mut write_bytes_total = 0;
    let mut read_bytes_total = 0;
    let mut list = Vec::with_capacity(options.concurrent);

    while let Some(j) = queue.recv().await {
        count += 1;

        match j.await? {
            Ok(stat) => {
                let dur = stat.end.duration_since(stat.start);
                total += dur;
                handshake_total = stat.handshake_ok.duration_since(stat.start);
                end_total += stat.end.duration_since(stat.handshake_ok);
                write_bytes_total += stat.write_bytes;
                read_bytes_total += stat.read_bytes;
                list.push(dur);
            },
            Err(err) => {
                eprintln!("{:?}", err);
                failed += 1;
            }
        }
    }

    let dur = start.elapsed();
    let succeeded = count - failed;
    let stat = latency(&mut list);

    println!("{} requests in {}s, {} failed", count, dur.as_secs_f64(), failed);

    println!("{:#?}", stat);

    println!("handshake mean: {:?}", handshake_total / (succeeded as u32));
    println!("write/sec: {}", (write_bytes_total as f64) / end_total.as_secs_f64());
    println!("read/sec: {}", (read_bytes_total as f64) / end_total.as_secs_f64());

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
    timeout: Option<Duration>,
    sender: mpsc::UnboundedSender<JoinHandle<io::Result<Stat>>>
}

struct Stat {
    start: Instant,
    handshake_ok: Instant,
    end: Instant,
    write_bytes: u64,
    read_bytes: u64
}

#[derive(Debug)]
struct StatResult {
    min: Duration,
    max: Duration,
    avg: Duration,
    p50: Duration,
    p75: Duration,
    p90: Duration,
    p99: Duration,
    stdev: f64
}

fn spawn_task(ctx: Arc<Context>) {
    let sender = ctx.sender.clone();

    let join = tokio::spawn(async move {
        let fut = async {
            let start = Instant::now();

            let stream = TcpStream::connect(&ctx.addr).await?;
            let mut input = io::Cursor::new(&ctx.input);
            let mut output = sink();

            let domain = DNSNameRef::try_from_ascii_str(&ctx.domain)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
            let mut stream = ctx.connector.connect(domain, stream).await?;
            let handshake_ok = Instant::now();

            stream.write_all(ctx.content.as_bytes()).await?;

            let (mut reader, mut writer) = split(stream);
            let mut read_fused = false;
            let mut write_fused = false;
            let mut write_bytes = ctx.content.len() as u64;
            let mut read_bytes = 0;
            while !read_fused || !write_fused {
                tokio::select!{
                    ret = async {
                        if !read_fused { copy(&mut reader, &mut output).await }
                        else { Pending2.await }
                    } => {
                        read_bytes = ret?;
                        read_fused = true;
                    },
                    ret = async {
                        if !write_fused { copy(&mut input, &mut writer).await }
                        else { Pending2.await }
                    } => {
                        write_bytes = ret?;
                        writer.shutdown().await?;
                        write_fused = true;
                    }
                }
            }
            let end = Instant::now();

            let stat = Stat {
                start, handshake_ok, end,
                write_bytes, read_bytes
            };
            Ok(stat) as io::Result<Stat>
        };

        let ret = if let Some(dur) = ctx.timeout {
            timeout(dur, fut).await
                .map_err(Into::into)
                .and_then(|ret| ret)
        } else {
            fut.await
        };

        if let Some(keep) = ctx.keep {
            if ctx.start.elapsed() <= keep {
                spawn_task(ctx);
            }
        }

        ret
    });

    let _ = sender.send(join);
}

fn latency(list: &mut [Duration]) -> Option<StatResult> {
    fn p(list: &[Duration], pct: f64) -> Duration {
        let n = list.len() as f64;
        let n = n * pct;
        let n = n.ceil() as usize;
        list[n]
    }

    list.sort();

    let min = list.first().copied()?;
    let max = list.last().copied()?;

    let avg = {
        let total: Duration = list.iter().sum();
        total / (list.len() as u32)
    };

    let stdev = {
        let n: f64 = list.iter()
            .map(|dur| dur.as_secs_f64() - avg.as_secs_f64())
            .map(|n| n.powi(2))
            .sum();
        let n = n / (list.len() as f64);
        n.sqrt()
    };

    let p50 = p(list, 0.5);
    let p75 = p(list, 0.75);
    let p90 = p(list, 0.90);
    let p99 = p(list, 0.99);

    Some(StatResult {
        min, max, avg,
        p50, p75, p90, p99,
        stdev
    })
}

struct Pending2;

impl Future for Pending2 {
    type Output = io::Result<u64>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Ctx<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

//! Relais SNI de bout en bout : vrai serveur sur des ports éphémères, fausse maison, clients
//! TLS réels.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::{net::SocketAddr, time::Duration};

use agendo_access_protocol::frame::{CloseCode, DEFAULT_INITIAL_WINDOW, Frame, GoAwayCode};
use relay_sni::{
    config::{Cidr, Limits, ProxyPolicy, SniConfig},
    proxy_protocol::encode_v2,
    server::{Listeners, Relay},
    testkit::{self, HOST, HouseConn, OTHER_HOST, ZONE},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

const CLIENT: &str = "203.0.113.7:51000";
const HOUSE_IP: &str = "198.51.100.9:40000";

struct TestRelay {
    relay: Relay,
    public: SocketAddr,
    tunnels: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

fn config(tweak: impl FnOnce(&mut SniConfig)) -> SniConfig {
    let mut c = SniConfig {
        zone: ZONE.into(),
        trusted_keys: testkit::trusted_keys(),
        proxy: ProxyPolicy::Required(vec!["127.0.0.1/32".parse::<Cidr>().unwrap()]),
        public_addr: "127.0.0.1:0".parse().unwrap(),
        tunnel_addr: "127.0.0.1:0".parse().unwrap(),
        metrics_addr: None,
        limits: Limits { shutdown_grace: Duration::from_millis(200), ..Limits::default() },
    };
    tweak(&mut c);
    c
}

async fn start(config: SniConfig) -> TestRelay {
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnels = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (public_addr, tunnels_addr) = (public.local_addr().unwrap(), tunnels.local_addr().unwrap());
    let relay = Relay::new(config);
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(relay.clone().run(Listeners { public, tunnels, metrics: None }, async {
        let _ = stopped.await;
    }));
    TestRelay { relay, public: public_addr, tunnels: tunnels_addr, stop: Some(stop), task }
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Maison connectée au port des tunnels (avec l'en-tête PROXY de `HOUSE_IP`), avant poignée de main.
async fn house(relay: &TestRelay) -> HouseConn<TcpStream> {
    let mut tcp = TcpStream::connect(relay.tunnels).await.unwrap();
    tcp.write_all(&encode_v2(addr(HOUSE_IP), relay.tunnels)).await.unwrap();
    HouseConn::new(tcp)
}

/// Maison prête qui sert `HOST` en TLS.
async fn tls_house(relay: &TestRelay, host: &str) -> std::sync::Arc<rustls::ClientConfig> {
    let mut h = house(relay).await;
    let Frame::Ready { initial_window, .. } = h.handshake(host).await else { unreachable!() };
    let (server, client) = testkit::tls_pair(host);
    tokio::spawn(testkit::serve_tls(h, initial_window, server));
    client
}

/// Client brut : en-tête PROXY de `source` puis les octets donnés.
async fn raw_client(relay: &TestRelay, source: &str, bytes: &[u8]) -> TcpStream {
    let mut tcp = TcpStream::connect(relay.public).await.unwrap();
    tcp.write_all(&encode_v2(addr(source), relay.public)).await.unwrap();
    tcp.write_all(bytes).await.unwrap();
    tcp
}

fn client_hello(host: &str) -> Vec<u8> {
    let (_, client) = testkit::tls_pair(host);
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap();
    let mut conn = rustls::ClientConnection::new(client, name).unwrap();
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).unwrap();
    }
    out
}

/// La connexion est-elle fermée par le relais (fin de flux ou erreur) dans le délai ?
async fn closed_within(tcp: &mut TcpStream, delay: Duration) -> bool {
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(delay, tcp.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => continue,
            Err(_) => return false,
        }
    }
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("toujours pas : {what}");
}

/// Prochaine trame qui n'est pas un `PING` (auquel la maison répond).
async fn next_non_ping(h: &mut HouseConn<TcpStream>) -> Option<Frame> {
    loop {
        match h.recv().await? {
            Frame::Ping { ts } => h.send(&Frame::Pong { ts }).await,
            other => return Some(other),
        }
    }
}

#[tokio::test]
async fn tls_end_to_end_through_the_relay() {
    let relay = start(config(|_| {})).await;
    let tls = tls_house(&relay, HOST).await;
    let stream = testkit::tls_client(relay.public, addr(CLIENT), HOST, tls).await.unwrap();
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = BufReader::new(rd).lines();
    wr.write_all(b"bonjour\n").await.unwrap();
    // Sans flush, rustls peut garder des enregistrements chiffrés en attente quand la socket
    // est pleine : ils ne partiraient jamais.
    wr.flush().await.unwrap();
    assert_eq!(lines.next_line().await.unwrap().unwrap(), format!("écho bonjour de {CLIENT}"));
    // Un gros envoi traverse plusieurs fenêtres.
    let big = "x".repeat(600 * 1024);
    wr.write_all(format!("{big}\n").as_bytes()).await.unwrap();
    wr.flush().await.unwrap();
    assert_eq!(lines.next_line().await.unwrap().unwrap().len(), "écho  de ".len() + big.len() + CLIENT.len());
    assert_eq!(relay.relay.metrics().streams.get(), 1);
    drop(wr);
    drop(lines);
    wait_for("flux refermé", || relay.relay.metrics().streams.get() == 0).await;
}

#[tokio::test]
async fn unknown_host_or_absent_house_is_closed() {
    let relay = start(config(|_| {})).await;
    let _tls = tls_house(&relay, HOST).await;
    let mut c = raw_client(&relay, CLIENT, &client_hello(OTHER_HOST)).await;
    assert!(closed_within(&mut c, Duration::from_secs(2)).await);
    let mut c = raw_client(&relay, CLIENT, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(closed_within(&mut c, Duration::from_secs(2)).await, "pas du TLS");
}

#[tokio::test]
async fn proxy_header_is_required_and_only_from_allowed_peers() {
    let relay = start(config(|_| {})).await;
    let _tls = tls_house(&relay, HOST).await;
    // Sans en-tête PROXY.
    let mut tcp = TcpStream::connect(relay.public).await.unwrap();
    tcp.write_all(&client_hello(HOST)).await.unwrap();
    assert!(closed_within(&mut tcp, Duration::from_secs(2)).await);

    // Pair non autorisé, sur les deux ports.
    let relay = start(config(|c| c.proxy = ProxyPolicy::Required(vec!["10.9.9.0/24".parse().unwrap()]))).await;
    let mut c = raw_client(&relay, CLIENT, &client_hello(HOST)).await;
    assert!(closed_within(&mut c, Duration::from_secs(2)).await);
    let mut h = house(&relay).await;
    assert!(closed_within(&mut h.io, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn mode_without_proxy_protocol() {
    let relay = start(config(|c| c.proxy = ProxyPolicy::Off)).await;
    let mut h = HouseConn::new(TcpStream::connect(relay.tunnels).await.unwrap());
    h.handshake(HOST).await;
    let mut tcp = TcpStream::connect(relay.public).await.unwrap();
    tcp.write_all(&client_hello(HOST)).await.unwrap();
    let Some(Frame::Open { client, .. }) = next_non_ping(&mut h).await else { panic!("OPEN attendu") };
    assert_eq!(client, tcp.local_addr().unwrap(), "adresse du pair TCP");
}

#[tokio::test]
async fn open_then_replay_of_the_client_hello() {
    let relay = start(config(|_| {})).await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    let hello = client_hello(HOST);
    let mut c = raw_client(&relay, CLIENT, &hello).await;
    let Some(Frame::Open { stream, client }) = next_non_ping(&mut h).await else { panic!("OPEN attendu") };
    assert_eq!(client, addr(CLIENT));
    let mut replayed = Vec::new();
    while replayed.len() < hello.len() {
        let Some(Frame::Data { stream: s, data }) = next_non_ping(&mut h).await else { panic!("DATA attendu") };
        assert_eq!(s, stream);
        replayed.extend_from_slice(&data);
    }
    assert_eq!(replayed, hello);
    // La maison répond, le client reçoit ; la maison ferme, le client voit la fin.
    h.send(&Frame::Data { stream, data: b"reponse".to_vec() }).await;
    h.send(&Frame::Close { stream, code: CloseCode::Normal }).await;
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut got)).await.unwrap().unwrap();
    assert_eq!(got, b"reponse");
    wait_for("flux retiré", || relay.relay.metrics().streams.get() == 0).await;
}

#[tokio::test]
async fn client_close_sends_close_to_the_house() {
    let relay = start(config(|_| {})).await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    let c = raw_client(&relay, CLIENT, &client_hello(HOST)).await;
    let Some(Frame::Open { stream, .. }) = next_non_ping(&mut h).await else { panic!() };
    drop(c);
    loop {
        match next_non_ping(&mut h).await {
            Some(Frame::Data { .. }) => continue,
            Some(Frame::Close { stream: s, code }) => {
                assert_eq!((s, code), (stream, CloseCode::Normal));
                break;
            }
            other => panic!("CLOSE attendu, reçu {other:?}"),
        }
    }
    wait_for("flux retiré", || relay.relay.metrics().streams.get() == 0).await;
}

#[tokio::test]
async fn relay_never_sends_beyond_the_window() {
    let window = 32 * 1024;
    let relay = start(config(|c| c.limits.initial_window = window)).await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    let mut c = raw_client(&relay, CLIENT, &client_hello(HOST)).await;
    let Some(Frame::Open { stream, .. }) = next_non_ping(&mut h).await else { panic!() };
    tokio::spawn(async move {
        let _ = c.write_all(&vec![0u8; 1 << 20]).await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let mut received = 0usize;
    let count = |frame: Option<Frame>, received: &mut usize| match frame {
        Some(Frame::Data { data, .. }) => *received += data.len(),
        other => panic!("DATA attendu, reçu {other:?}"),
    };
    while received < window as usize {
        count(next_non_ping(&mut h).await, &mut received);
    }
    assert_eq!(received, window as usize, "pas un octet de plus que la fenêtre");
    // Plus rien sans crédit.
    let quiet = tokio::time::timeout(Duration::from_millis(300), h.recv()).await;
    assert!(quiet.is_err(), "trame reçue sans crédit : {quiet:?}");
    h.send(&Frame::Window { stream, increment: 1000 }).await;
    let before = received;
    while received < before + 1000 {
        count(next_non_ping(&mut h).await, &mut received);
    }
    assert_eq!(received, before + 1000);
}

#[tokio::test]
async fn house_exceeding_the_window_gets_close_flow_control() {
    let window = 16 * 1024;
    let relay = start(config(|c| c.limits.initial_window = window)).await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    let mut c = raw_client(&relay, CLIENT, &client_hello(HOST)).await;
    let Some(Frame::Open { stream, .. }) = next_non_ping(&mut h).await else { panic!() };
    // Toute la fenêtre d'un coup ; le relais en rend une partie une fois écrite chez le client.
    h.send(&Frame::Data { stream, data: vec![1; window as usize] }).await;
    let mut granted = 0usize;
    while let Ok(frame) = tokio::time::timeout(Duration::from_millis(300), next_non_ping(&mut h)).await {
        match frame {
            Some(Frame::Window { increment, .. }) => granted += increment as usize,
            Some(Frame::Data { .. }) => {}
            other => panic!("inattendu : {other:?}"),
        }
    }
    // Un octet de plus que le crédit restant.
    h.send(&Frame::Data { stream, data: vec![1; granted + 1] }).await;
    loop {
        match next_non_ping(&mut h).await {
            Some(Frame::Data { .. }) => continue,
            Some(Frame::Close { stream: s, code }) => {
                assert_eq!((s, code), (stream, CloseCode::FlowControl));
                break;
            }
            other => panic!("CLOSE 3 attendu, reçu {other:?}"),
        }
    }
    assert!(closed_within(&mut c, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn newer_connection_replaces_the_older_one() {
    let relay = start(config(|_| {})).await;
    let mut old = house(&relay).await;
    old.handshake(HOST).await;
    let mut new = house(&relay).await;
    new.handshake(HOST).await;
    match next_non_ping(&mut old).await {
        Some(Frame::GoAway { code, .. }) => assert_eq!(code, GoAwayCode::Replaced),
        other => panic!("GOAWAY 1 attendu, reçu {other:?}"),
    }
    drop(old);
    tokio::time::sleep(Duration::from_millis(100)).await;
    // La fin de l'ancien tunnel ne désinscrit pas le nouveau.
    let _c = raw_client(&relay, CLIENT, &client_hello(HOST)).await;
    assert!(matches!(next_non_ping(&mut new).await, Some(Frame::Open { .. })));
    assert_eq!(relay.relay.metrics().tunnels.get(), 1);
}

#[tokio::test]
async fn unanswered_pings_close_the_tunnel() {
    let relay = start(config(|c| c.limits.ping_interval = Duration::from_millis(100))).await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    let mut pings = 0;
    while let Some(frame) = h.recv().await {
        match frame {
            Frame::Ping { .. } => pings += 1,
            Frame::GoAway { .. } => {}
            other => panic!("inattendu : {other:?}"),
        }
    }
    assert_eq!(pings, 3, "coupure après 3 pings sans réponse");
    wait_for("tunnel retiré", || relay.relay.metrics().tunnels.get() == 0).await;
}

#[tokio::test]
async fn answered_pings_keep_the_tunnel() {
    let relay = start(config(|c| c.limits.ping_interval = Duration::from_millis(50))).await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    for _ in 0..8 {
        let Some(Frame::Ping { ts }) = h.recv().await else { panic!("PING attendu") };
        h.send(&Frame::Pong { ts }).await;
    }
}

#[tokio::test]
async fn token_expiry_sends_goaway_token_expired() {
    let relay = start(config(|_| {})).await;
    let mut h = house(&relay).await;
    let token = testkit::tunnel_token(HOST, 2);
    assert!(matches!(h.handshake_with(&token, &testkit::house_key()).await, Frame::Ready { .. }));
    let frame = tokio::time::timeout(Duration::from_secs(4), next_non_ping(&mut h)).await.unwrap();
    assert!(matches!(frame, Some(Frame::GoAway { code: GoAwayCode::TokenExpired, .. })), "{frame:?}");
}

#[tokio::test]
async fn protocol_error_after_ready() {
    let relay = start(config(|_| {})).await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    h.send(&Frame::Open { stream: 1, client: addr(CLIENT) }).await;
    assert!(matches!(next_non_ping(&mut h).await, Some(Frame::GoAway { code: GoAwayCode::ProtocolError, .. })));
    assert_eq!(next_non_ping(&mut h).await, None);
}

#[tokio::test]
async fn shutdown_sends_goaway_and_stops() {
    let mut relay = start(config(|_| {})).await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    relay.stop.take().unwrap().send(()).unwrap();
    assert!(matches!(next_non_ping(&mut h).await, Some(Frame::GoAway { code: GoAwayCode::Shutdown, .. })));
    tokio::time::timeout(Duration::from_secs(3), relay.task).await.unwrap().unwrap();
    assert!(TcpStream::connect(relay.public).await.is_err(), "plus d'écoute");
}

#[tokio::test]
async fn connections_are_limited_per_ip() {
    let relay = start(config(|c| c.limits.max_connections_per_ip = 2)).await;
    let mut a = raw_client(&relay, CLIENT, b"").await;
    let mut b = raw_client(&relay, CLIENT, b"").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c = raw_client(&relay, CLIENT, b"").await;
    assert!(closed_within(&mut c, Duration::from_secs(1)).await, "troisième refusée");
    assert!(!closed_within(&mut a, Duration::from_millis(200)).await);
    assert!(!closed_within(&mut b, Duration::from_millis(200)).await);
    let mut other = raw_client(&relay, "203.0.113.8:1", b"").await;
    assert!(!closed_within(&mut other, Duration::from_millis(200)).await, "autre IP admise");
}

#[tokio::test]
async fn tunnels_are_limited_per_ip_and_streams_per_tunnel() {
    let relay = start(config(|c| {
        c.limits.max_tunnels_per_ip = 1;
        c.limits.max_streams_per_tunnel = 1;
    }))
    .await;
    let mut h = house(&relay).await;
    h.handshake(HOST).await;
    let mut second = house(&relay).await;
    assert!(closed_within(&mut second.io, Duration::from_secs(1)).await, "second tunnel de la même IP refusé");
    let _a = raw_client(&relay, CLIENT, &client_hello(HOST)).await;
    assert!(matches!(next_non_ping(&mut h).await, Some(Frame::Open { .. })));
    let mut b = raw_client(&relay, "203.0.113.8:1", &client_hello(HOST)).await;
    assert!(closed_within(&mut b, Duration::from_secs(2)).await, "un seul flux par tunnel");
}

#[tokio::test]
async fn slow_client_hello_times_out() {
    let relay = start(config(|c| c.limits.hello_timeout = Duration::from_millis(200))).await;
    let hello = client_hello(HOST);
    let mut c = raw_client(&relay, CLIENT, &hello[..10]).await;
    assert!(closed_within(&mut c, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn initial_window_is_announced() {
    let relay = start(config(|_| {})).await;
    let mut h = house(&relay).await;
    let Frame::Ready { host, initial_window, ping_interval_secs } = h.handshake(HOST).await else { unreachable!() };
    assert_eq!((host.as_str(), initial_window, ping_interval_secs), (HOST, DEFAULT_INITIAL_WINDOW, 25));
}

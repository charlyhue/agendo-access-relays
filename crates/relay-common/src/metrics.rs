//! Métriques minimales (connexions, flux, push par statut), au format texte de Prometheus, sur
//! un port interne : `GET /metrics` ; `GET /sante` répond `ok`.
//!
//! Aucune étiquette ne porte de donnée d'une maison (ni nom d'hôte, ni IP) : seulement des
//! valeurs fixes choisies par le code.

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// Compteur croissant.
#[derive(Debug, Clone, Default)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    pub fn inc(&self) {
        self.add(1);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Jauge (valeur qui monte et descend).
#[derive(Debug, Clone, Default)]
pub struct Gauge(Arc<AtomicI64>);

impl Gauge {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
enum Value {
    Counter(Counter),
    Gauge(Gauge),
}

#[derive(Debug)]
struct Series {
    name: &'static str,
    help: &'static str,
    labels: Vec<(&'static str, &'static str)>,
    value: Value,
}

/// Ensemble des métriques d'un relais.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    series: Arc<Mutex<Vec<Series>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Nouveau compteur `name{labels}`.
    pub fn counter(&self, name: &'static str, help: &'static str, labels: &[(&'static str, &'static str)]) -> Counter {
        let counter = Counter::default();
        self.push(name, help, labels, Value::Counter(counter.clone()));
        counter
    }

    /// Nouvelle jauge `name{labels}`.
    pub fn gauge(&self, name: &'static str, help: &'static str, labels: &[(&'static str, &'static str)]) -> Gauge {
        let gauge = Gauge::default();
        self.push(name, help, labels, Value::Gauge(gauge.clone()));
        gauge
    }

    fn push(&self, name: &'static str, help: &'static str, labels: &[(&'static str, &'static str)], value: Value) {
        self.lock().push(Series { name, help, labels: labels.to_vec(), value });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Series>> {
        self.series.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Texte Prometheus : `# HELP` et `# TYPE` une fois par nom, puis chaque série.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let series = self.lock();
        let mut out = String::new();
        let mut done: Vec<&str> = Vec::new();
        for first in series.iter() {
            if done.contains(&first.name) {
                continue;
            }
            done.push(first.name);
            let kind = match first.value {
                Value::Counter(_) => "counter",
                Value::Gauge(_) => "gauge",
            };
            let _ = writeln!(out, "# HELP {} {}", first.name, first.help);
            let _ = writeln!(out, "# TYPE {} {kind}", first.name);
            for s in series.iter().filter(|s| s.name == first.name) {
                let value = match &s.value {
                    Value::Counter(c) => c.get().to_string(),
                    Value::Gauge(g) => g.get().to_string(),
                };
                let labels: Vec<String> = s.labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
                if labels.is_empty() {
                    let _ = writeln!(out, "{} {value}", s.name);
                } else {
                    let _ = writeln!(out, "{}{{{}}} {value}", s.name, labels.join(","));
                }
            }
        }
        out
    }
}

/// Requête de plus de 4 Kio ou plus lente que 5 s : abandonnée.
const MAX_REQUEST: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn answer(mut stream: TcpStream, registry: Registry) {
    let mut buf = vec![0u8; MAX_REQUEST];
    let mut len = 0;
    let read = async {
        while len < buf.len() {
            let n = stream.read(buf.get_mut(len..).unwrap_or_default()).await.ok()?;
            if n == 0 {
                return None;
            }
            len += n;
            if buf.get(..len).is_some_and(|b| b.windows(4).any(|w| w == b"\r\n\r\n")) {
                return Some(());
            }
        }
        None
    };
    if tokio::time::timeout(REQUEST_TIMEOUT, read).await.ok().flatten().is_none() {
        return;
    }
    let request = buf.get(..len).unwrap_or_default();
    let path = request.split(|b| *b == b' ').nth(1).unwrap_or_default();
    let (status, body) = if !request.starts_with(b"GET ") {
        ("405 Method Not Allowed", String::new())
    } else {
        match path {
            b"/metrics" => ("200 OK", registry.render()),
            b"/sante" => ("200 OK", "ok\n".to_owned()),
            _ => ("404 Not Found", String::new()),
        }
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(REQUEST_TIMEOUT, stream.write_all(response.as_bytes())).await;
    let _ = stream.shutdown().await;
}

/// Sert les métriques jusqu'à `shutdown`.
pub async fn serve(listener: TcpListener, registry: Registry, shutdown: impl Future<Output = ()>) {
    // Port interne : peu de clients à la fois suffisent.
    let slots = Arc::new(tokio::sync::Semaphore::new(16));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let registry = registry.clone();
                tokio::spawn(async move {
                    answer(stream, registry).await;
                    drop(permit);
                });
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn render_groups_series_by_name() {
        let r = Registry::new();
        let sent = r.counter("relay_push_requests_total", "Requêtes de push par statut.", &[("status", "sent")]);
        let quota = r.counter("relay_push_requests_total", "Requêtes de push par statut.", &[("status", "quota")]);
        let tunnels = r.gauge("relay_sni_tunnels", "Tunnels ouverts.", &[]);
        sent.add(3);
        quota.inc();
        tunnels.inc();
        tunnels.inc();
        tunnels.dec();
        assert_eq!(
            r.render(),
            "# HELP relay_push_requests_total Requêtes de push par statut.\n\
             # TYPE relay_push_requests_total counter\n\
             relay_push_requests_total{status=\"sent\"} 3\n\
             relay_push_requests_total{status=\"quota\"} 1\n\
             # HELP relay_sni_tunnels Tunnels ouverts.\n\
             # TYPE relay_sni_tunnels gauge\n\
             relay_sni_tunnels 1\n"
        );
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn serves_metrics_and_health() {
        let r = Registry::new();
        r.counter("x_total", "X.", &[]).inc();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(listener, r, async {
            let _ = stopped.await;
        }));
        let metrics = get(addr, "/metrics").await;
        assert!(metrics.starts_with("HTTP/1.1 200 OK\r\n"), "{metrics}");
        assert!(metrics.ends_with("x_total 1\n"), "{metrics}");
        assert!(get(addr, "/sante").await.ends_with("\r\n\r\nok\n"));
        assert!(get(addr, "/autre").await.starts_with("HTTP/1.1 404"));
        stop.send(()).unwrap();
        task.await.unwrap();
    }
}

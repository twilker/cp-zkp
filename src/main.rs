use eventador::{Eventador, SinkExt, StreamExt};
use tokio::time::{sleep, Duration, Instant};
use once_cell::sync::Lazy;

static INSTANT: Lazy<Instant> = Lazy::new(|| Instant::now());

pub struct Subscriber {
    eventbus: Eventador,
    i: u16
}

impl Subscriber {
    pub fn new(i: u16, eventbus: Eventador) -> Self {
        Self {
            i, eventbus
        }
    }

    pub async fn start(self) {
        let mut subscription = self.eventbus.async_subscriber::<Event>();
        println!("subscribed {}", self.i);
        let value = subscription.next().await.expect("Something went wrong").value;
        println!("pre sleep {} - {}ms since start", self.i, INSTANT.elapsed().as_millis());
        let now = Instant::now();
        sleep(Duration::from_millis(1000)).await;
        println!("{}: {:?} - {}ms - {}ms since start", self.i, value, now.elapsed().as_millis(), INSTANT.elapsed().as_millis());
    }
}

#[derive(Debug)]
pub struct Event {
    pub value: u16
}

#[tokio::main]
async fn main() {
    let eventbus = Eventador::new(1024).unwrap();

    let mut publisher = eventbus.async_publisher::<Event>(512);

    for i in 1..100 {
        let subscriber = Subscriber::new(i, eventbus.clone());
        tokio::spawn(subscriber.start());
    }

    //wait for events to subscribe
    sleep(Duration::from_millis(1000)).await;

    println!("sending at {}", INSTANT.elapsed().as_millis());
    publisher.send(Event { value: 1234 }).await.expect("Something went wrong");
    println!("send finished");

    sleep(Duration::from_millis(10000)).await;
    println!("sleep finished");
}
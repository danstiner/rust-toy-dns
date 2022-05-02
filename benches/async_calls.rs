use std::{
    future::{self, Future},
    pin::Pin,
};

use async_trait::async_trait;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::sync::oneshot;

fn work(n: u64) -> u64 {
    black_box(n)
}

fn sync_work(n: u64) -> u64 {
    work(n)
}

async fn async_work(n: u64) -> u64 {
    work(n)
}

fn async_work_boxed(n: u64) -> Pin<Box<dyn Future<Output = u64>>> {
    Box::pin(future::ready(work(n)))
}

async fn async_work_spawn(n: u64) -> u64 {
    let (sender, receiver) = oneshot::channel();

    tokio::spawn(async move {
        sender.send(n).unwrap();
    });

    receiver.await.unwrap()
}

struct Worker {}

impl Worker {
    fn sync_work(&self, n: u64) -> u64 {
        work(n)
    }

    async fn async_work(&self, n: u64) -> u64 {
        work(n)
    }
}

#[async_trait]
impl GenericWorker for Worker {
    async fn generic_async_work(&self, n: u64) -> u64 {
        work(n)
    }
}

#[async_trait]
trait GenericWorker {
    async fn generic_async_work(&self, n: u64) -> u64;
}

// This was an experiment to estimate the overhead of boxed futures and #[async_trait].
// Roughly:
// - a sync fn call was taken as the baseline, about one nanosecond
// - an async fn call took about twice as long (returns a future impl directly)
// - an async_trait fn took about twelve times as long (returns a boxed future)
// - an async_trait fn on a trait object took about thirteen times as long
//
// These differences are significant at some scales, but not for a DNS server. I shouldn't be
// worrying about this and just use async_trait freely.
fn criterion_benchmark(c: &mut Criterion) {
    let num = 20;
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // Test bare function calls
    c.bench_function("sync fn", |b| b.iter(|| sync_work(black_box(num))));
    c.bench_with_input(BenchmarkId::new("async fn", num), &num, |b, &n| {
        b.to_async(&runtime).iter(|| async_work(black_box(n)));
    });
    c.bench_with_input(BenchmarkId::new("async fn boxed", num), &num, |b, &n| {
        b.to_async(&runtime).iter(|| async_work_boxed(black_box(n)));
    });
    c.bench_with_input(BenchmarkId::new("async fn oneshot from spawned task", num), &num, |b, &n| {
        b.to_async(&runtime).iter(|| async_work_spawn(black_box(n)));
    });

    // Test method calls on struct
    let worker = Worker {};

    c.bench_function("sync method", |b| {
        b.iter(|| worker.sync_work(black_box(num)))
    });

    c.bench_with_input(BenchmarkId::new("async method", num), &num, |b, &n| {
        b.to_async(&runtime)
            .iter(|| worker.async_work(black_box(n)));
    });

    c.bench_with_input(
        BenchmarkId::new("async method, trait impl", num),
        &num,
        |b, &n| {
            b.to_async(&runtime)
                .iter(|| worker.generic_async_work(black_box(n)));
        },
    );

    let g: &dyn GenericWorker = &worker;

    c.bench_with_input(
        BenchmarkId::new("async method, trait object", num),
        &num,
        |b, &n| {
            b.to_async(&runtime)
                .iter(|| g.generic_async_work(black_box(n)));
        },
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

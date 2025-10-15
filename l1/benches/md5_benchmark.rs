use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use l1::md5;
use reference_md5;

fn bench_our_md5(c: &mut Criterion) {
    let data = b"The quick brown fox jumps over the lazy dog";
    c.bench_function("our_md5", |b| b.iter(|| md5(black_box(data))));
}

fn bench_reference_md5(c: &mut Criterion) {
    let data = b"The quick brown fox jumps over the lazy dog";
    c.bench_function("reference_md5", |b| b.iter(|| {
        reference_md5::compute(black_box(data))
    }));
}

criterion_group!(benches, bench_our_md5, bench_reference_md5);
criterion_main!(benches);

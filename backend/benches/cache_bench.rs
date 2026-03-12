//! Cache benchmarks

use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_cache_key_generation(c: &mut Criterion) {
    c.bench_function("cache_key_generation", |b| {
        b.iter(|| {
            black_box("github.com:/owner/repo/main/file.txt?raw=true".to_string());
            black_box("registry:nginx/latest".to_string());
            black_box("registry::sha256:abc123...".to_string());
        });
    });
}

criterion_group!(benches, bench_cache_key_generation);
criterion_main!(benches);

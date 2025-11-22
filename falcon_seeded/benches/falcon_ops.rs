use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use falcon_seeded::{keypair_with, sign_with, verify, FillBytes, PK_LEN, SK_LEN};
use std::sync::{Arc, Mutex};

// Simple counter-based DRBG for benchmarking
struct BenchDrbg {
    counter: Mutex<u64>,
}

impl BenchDrbg {
    fn new() -> Self {
        Self {
            counter: Mutex::new(0),
        }
    }
}

impl FillBytes for BenchDrbg {
    fn fill(&self, out: &mut [u8]) {
        let mut ctr = self.counter.lock().unwrap();
        for byte in out.iter_mut() {
            *byte = (*ctr & 0xFF) as u8;
            *ctr = ctr.wrapping_add(1);
        }
    }
}

fn benchmark_keypair_generation(c: &mut Criterion) {
    c.bench_function("falcon_keypair_generation", |b| {
        b.iter(|| {
            let drbg = Arc::new(BenchDrbg::new());
            let result = keypair_with(drbg);
            black_box(result)
        });
    });
}

fn benchmark_signing(c: &mut Criterion) {
    // Pre-generate keypair
    let drbg_keygen = Arc::new(BenchDrbg::new());
    let (_pk, sk) = keypair_with(drbg_keygen).unwrap();

    let mut group = c.benchmark_group("falcon_signing");

    // Benchmark different message sizes
    for size in [32, 64, 128, 256, 512, 1024].iter() {
        let msg = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let drbg = Arc::new(BenchDrbg::new());
                let sig = sign_with(drbg, &sk, &msg).unwrap();
                black_box(sig)
            });
        });
    }

    group.finish();
}

fn benchmark_verification(c: &mut Criterion) {
    // Pre-generate keypair and signature
    let drbg_keygen = Arc::new(BenchDrbg::new());
    let (pk, sk) = keypair_with(drbg_keygen).unwrap();

    let mut group = c.benchmark_group("falcon_verification");

    // Benchmark different message sizes
    for size in [32, 64, 128, 256, 512, 1024].iter() {
        let msg = vec![0x42u8; *size];

        // Pre-generate signature
        let drbg_sign = Arc::new(BenchDrbg::new());
        let sig = sign_with(drbg_sign, &sk, &msg).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let result = verify(&pk, &msg, &sig);
                black_box(result)
            });
        });
    }

    group.finish();
}

fn benchmark_sign_verify_roundtrip(c: &mut Criterion) {
    let drbg_keygen = Arc::new(BenchDrbg::new());
    let (pk, sk) = keypair_with(drbg_keygen).unwrap();

    c.bench_function("falcon_sign_verify_roundtrip", |b| {
        let msg = b"benchmark message";

        b.iter(|| {
            // Sign
            let drbg_sign = Arc::new(BenchDrbg::new());
            let sig = sign_with(drbg_sign, &sk, msg).unwrap();

            // Verify
            let result = verify(&pk, msg, &sig);

            black_box(result)
        });
    });
}

fn benchmark_memory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon_memory_ops");

    // Benchmark key zeroization overhead
    group.bench_function("keypair_with_zeroization", |b| {
        b.iter(|| {
            let drbg = Arc::new(BenchDrbg::new());
            let (pk, sk) = keypair_with(drbg).unwrap();
            // sk is automatically zeroized on drop
            drop(sk);
            black_box(pk)
        });
    });

    // Benchmark signature allocation
    group.bench_function("signature_allocation", |b| {
        let drbg_keygen = Arc::new(BenchDrbg::new());
        let (_pk, sk) = keypair_with(drbg_keygen).unwrap();
        let msg = b"test message";

        b.iter(|| {
            let drbg = Arc::new(BenchDrbg::new());
            let sig = sign_with(drbg, &sk, msg).unwrap();
            black_box(sig)
        });
    });

    group.finish();
}

fn benchmark_drbg_overhead(c: &mut Criterion) {
    c.bench_function("drbg_creation", |b| {
        b.iter(|| {
            let drbg = Arc::new(BenchDrbg::new());
            black_box(drbg)
        });
    });

    c.bench_function("drbg_fill_1kb", |b| {
        let drbg = Arc::new(BenchDrbg::new());
        let mut buffer = vec![0u8; 1024];

        b.iter(|| {
            drbg.fill(&mut buffer);
            black_box(&buffer)
        });
    });
}

fn benchmark_constant_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("constant_sizes");

    group.bench_function("pk_allocation", |b| {
        b.iter(|| {
            let pk = [0u8; PK_LEN];
            black_box(pk)
        });
    });

    group.bench_function("sk_allocation", |b| {
        b.iter(|| {
            let sk = [0u8; SK_LEN];
            black_box(sk)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_keypair_generation,
    benchmark_signing,
    benchmark_verification,
    benchmark_sign_verify_roundtrip,
    benchmark_memory_operations,
    benchmark_drbg_overhead,
    benchmark_constant_sizes
);

criterion_main!(benches);

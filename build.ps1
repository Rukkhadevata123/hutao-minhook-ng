cd C:\Users\rukkh\hutao-minhook-ng\src
cl /c /O2 /TC hutao_seh_stub.c
lib /OUT:hutao_seh_stub.lib hutao_seh_stub.obj
del hutao_seh_stub.obj

cd C:\Users\rukkh\hutao-minhook-ng
$env:RUSTFLAGS="-Lnative=src"
cargo clippy --fix --allow-dirty --allow-staged
cargo fmt
cargo build --release
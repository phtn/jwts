c:
	cargo check

r:
	cargo run

w:
	cargo watch -x run

t:
	cargo test --test api

b:
	@cargo build --release && clear && \
	    ./target/release/jwts

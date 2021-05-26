# file-loader
Rust library for storing encrypted files at compile time in the binary.

Reading, writing and saving to the drive for these files is allowed.

## Example
```rust
let mut file: InnerFile = f_create!("Cargo.toml", enc!("key"));
```
## Disclaimer
Version yet not ready for the release! <br>

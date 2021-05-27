# file-loader
Rust library for storing encrypted files at compile time in the binary.

`Reading`, `writing` and `saving to the drive` for these files is allowed, but of course any changes in the memory won't be saved after process termination.

## Example
```rust
#[macro_use] extern crate file_loader as fl;
file_loader_initialize!();


fn main() {
    // Method 1
    let x = file_loader_new!("Cargo.toml");

    // Method 2
    let x = fl::InnerFile::new_from_fload(f_load!("Cargo.toml"));


    println!("{}\n", x.get_key());
    println!("\n{}", x);
}
```

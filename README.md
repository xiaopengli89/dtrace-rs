# dtrace
Rust-like bindings to dtrace.

```rust
let pid = 1324;
let mut dt = dtrace::Dtrace::new().unwrap();
dt.setopt_c(c"strsize", c"4096").unwrap();
dt.setopt_c(c"bufsize", c"4m").unwrap();
dt.exec_program(&format!(
    r#"pid{}::__exit:entry{{printf("exit"); exit(0)}}"#,
    pid
))
.unwrap();
dt.go().unwrap();

println!("waiting for exit...");
while let Ok(false) = dt.work(|output| {
    println!(">> {output}");
}) {}
dt.stop().unwrap();
```

use std::{env, ffi};

fn main() {
    let pid: i32 = env::args().skip(1).next().unwrap().parse().unwrap();

    let mut dt = dtrace::Dtrace::new().unwrap();
    dt.setopt(c"strsize", c"4096").unwrap();
    dt.setopt(c"bufsize", c"4m").unwrap();
    let script = ffi::CString::new(format!(
        r#"pid{}::__exit:entry{{printf("exit"); exit(0)}}"#,
        pid
    ))
    .unwrap();
    dt.exec_program(&script).unwrap();
    dt.go().unwrap();

    println!("waiting for exit...");
    while let Ok(false) = dt.work(|output| {
        println!(">> {output}");
    }) {}
    dt.stop().unwrap();
}

fn main() {
    let values = vec![1, 2, 3];
    // clippy::needless_range_loop, a clippy::all lint.
    for i in 0..values.len() {
        println!("{}", values[i]);
    }
}

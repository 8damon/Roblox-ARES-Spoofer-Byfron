fn main() {
    let mut res = winresource::WindowsResource::new();

    res.set("CompanyName", "ARES Systems");
    res.set("FileDescription", "ARES Systems RS");
    res.set("ProductName", "T-ARES-RS");
    res.set("LegalCopyright", "ARES Systems");
    res.set("ProductVersion", "2.0.3");
    res.set("FileVersion", "2.0.3");

    if let Err(err) = res.compile() {
        panic!("failed to compile Windows resources: {err}");
    }
}

//! Wycheproof test vectors — same 574 the asm gates on.
use p256_verify::verify;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}

fn main() {
    let src = std::fs::read_to_string("../wycheproof_vectors.h")
        .expect("run from p256_rust/ with ../wycheproof_vectors.h present");

    // Format: { tcId, expect, "comment", "flags", "pub", "hash", "sig" },
    // Hex strings span multiple lines via C string concat — strip quotes/ws.
    let re = regex::Regex::new(
        r#"(?s)\{\s*(\d+),\s*(\d+),\s*"[^"]*",\s*"[^"]*",\s*((?:"[0-9a-f]*"\s*)+),\s*((?:"[0-9a-f]*"\s*)+),\s*((?:"[0-9a-f]*"\s*)+)\s*\}"#
    ).unwrap();
    let clean = |s: &str| -> String { s.chars().filter(|c| c.is_ascii_hexdigit()).collect() };

    let (mut pass, mut fail, mut valid_pass, mut invalid_pass) = (0, 0, 0, 0);
    for cap in re.captures_iter(&src) {
        let tc_id: u32 = cap[1].parse().unwrap();
        let expect: u32 = cap[2].parse().unwrap();
        let pub_key = hex(&clean(&cap[3]));
        let hash = hex(&clean(&cap[4]));
        let sig = hex(&clean(&cap[5]));
        let got = verify(&sig, &pub_key, &hash);
        if got == (expect == 1) {
            pass += 1;
            if expect == 1 { valid_pass += 1 } else { invalid_pass += 1 }
        } else {
            fail += 1;
            if fail <= 5 {
                eprintln!("FAIL tc{}: expect={} got={}  sig={}B pub={}B hash={}B",
                    tc_id, expect, got as u32, sig.len(), pub_key.len(), hash.len());
            }
        }
    }
    println!("{} pass, {} fail ({} valid + {} invalid)", pass, fail, valid_pass, invalid_pass);
    assert_eq!(pass, 574);
    assert_eq!(fail, 0);
}

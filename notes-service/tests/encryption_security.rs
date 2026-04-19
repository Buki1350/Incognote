use incognote_notes::services::{sanitize_note_content, EncryptionService};

#[test]
fn encrypted_note_can_be_decrypted_back() {
    let service = EncryptionService::from_passphrase("this-is-a-long-encryption-secret").unwrap();
    let encrypted = service.encrypt("line one\nline two").unwrap();
    let decrypted = service.decrypt(&encrypted).unwrap();

    assert_eq!(decrypted, "line one\nline two");
}

#[test]
fn sanitize_prevents_script_injection_markup() {
    let raw = "<img src=x onerror=alert('xss')>";
    let safe = sanitize_note_content(raw);

    assert!(!safe.contains("<img"));
    assert!(safe.contains("&lt;img"));
}

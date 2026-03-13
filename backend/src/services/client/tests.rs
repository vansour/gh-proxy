use super::HttpError;

#[test]
fn test_http_error_display() {
    let error = HttpError("test error".to_string());
    assert_eq!(error.to_string(), "test error");
}

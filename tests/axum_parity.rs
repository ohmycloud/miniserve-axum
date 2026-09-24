use reqwest::{StatusCode, blocking::Client, header};
use rstest::rstest;
use select::{
    document::Document,
    predicate::{Attr, Name, Predicate},
};

mod fixtures;
use fixtures::{Error, TestServer, reqwest_client, server};

#[rstest]
fn file_responses_support_head_and_ranges(
    server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    let url = server.url().join("test.txt")?;
    let head = reqwest_client
        .head(url.clone())
        .send()?
        .error_for_status()?;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers().get(header::CONTENT_LENGTH).unwrap(), "14");
    assert!(head.bytes()?.is_empty());

    let range = reqwest_client
        .get(url)
        .header(header::RANGE, "bytes=0-3")
        .send()?
        .error_for_status()?;
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(range.text()?, "Test");
    Ok(())
}

#[rstest]
fn external_file_links_keep_subdirectories(
    #[with(&["--file-external-url", "https://downloads.example/files"])] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    let body = reqwest_client
        .get(server.url().join("dira/")?)
        .send()?
        .error_for_status()?;
    let page = Document::from_read(body)?;
    let link = page
        .find(Name("a").and(Attr("class", "file")))
        .find(|node| node.text() == "test.txt")
        .and_then(|node| node.attr("href").map(str::to_owned));
    assert_eq!(
        link.as_deref(),
        Some("https://downloads.example/files/dira/test.txt")
    );
    Ok(())
}

#[rstest]
fn compression_is_opt_in(
    #[with(&["--compress-response"])] server: TestServer,
    reqwest_client: Client,
) -> Result<(), Error> {
    let response = reqwest_client
        .get(server.url())
        .header(header::ACCEPT_ENCODING, "gzip")
        .send()?
        .error_for_status()?;
    assert_eq!(
        response.headers().get(header::CONTENT_ENCODING).unwrap(),
        "gzip"
    );
    Ok(())
}

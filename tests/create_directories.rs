use crate::fixtures::{Error, TestServer, server};
use reqwest::blocking::{
    Client,
    multipart::{Form, Part},
};
use rstest::rstest;
use select::{
    document::Document,
    predicate::{Attr, Text},
};

mod fixtures;

/// This should work because the flags for uploading files and creating directories
/// are set, and the directory name and path are valid.

#[rstest]
fn creating_directories_works(
    #[with(&["--upload-files", "--mkdir"])] server: TestServer,
) -> Result<(), Error> {
    let test_directory_name = "hello";

    // Before creating, check whether the directory does not yet exis.
    let body = reqwest::blocking::get(server.url())?.error_for_status()?;
    let parsed = Document::from_read(body)?;
    assert!(parsed.find(Text).all(|x| x.text() != test_directory_name));

    // Perform the actual creating.
    let create_action = parsed
        .find(Attr("id", "mkdir"))
        .next()
        .expect("Couldn't find element with id=mkdir")
        .attr("action")
        .expect("Directory form doesn't have action attribute");

    let form = Form::new();
    let part = Part::text(test_directory_name);
    let form = form.part("mkdir", part);

    let client = Client::new();
    client
        .post(server.url().join(create_action)?)
        .multipart(form)
        .send()?
        .error_for_status()?;
    // After creating, check whether the directory is now getting listed.
    let body = reqwest::blocking::get(server.url())?;
    let parsed = Document::from_read(body)?;

    assert!(
        parsed
            .find(Text)
            .any(|x| x.text() == test_directory_name.to_owned() + "/")
    );

    Ok(())
}

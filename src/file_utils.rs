use std::path::{Component, Path, PathBuf};

/// Guarantee that the path is relative and cannot traverse back to parent directories
/// and optionally prevent traversing hidden directories.
///
/// See the unit tests tests::test_sanitize_path* for examples
pub fn sanitize_path(path: impl AsRef<Path>, traverse_hidden: bool) -> Option<PathBuf> {
    let mut buf = PathBuf::new();

    for comp in path.as_ref().components() {
        match comp {
            Component::Normal(name) => buf.push(name),
            Component::ParentDir => {
                buf.pop();
            }
            _ => (),
        }
    }

    // Double check that all components are Normal and check for hidden dirs
    for comp in buf.components() {
        match comp {
            Component::Normal(_) if traverse_hidden => (),
            Component::Normal(name) if !name.to_str()?.starts_with('.') => (),
            _ => return None,
        }
    }
    Some(buf)
}

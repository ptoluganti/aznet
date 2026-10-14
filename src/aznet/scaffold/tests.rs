use std::collections::BTreeSet;

use clap::ValueEnum;

use super::*;

fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            walk(&p, root, out);
        } else {
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(
                rel.strip_suffix(".tmpl")
                    .expect("template files end in .tmpl")
                    .into(),
            );
        }
    }
}

#[test]
fn every_template_file_is_registered() {
    for t in Template::value_variants() {
        let spec = spec(*t);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join(spec.dir);
        let mut on_disk = BTreeSet::new();
        walk(&root, &root, &mut on_disk);
        let listed: BTreeSet<String> = spec.files.iter().map(|f| f.path.to_string()).collect();
        assert_eq!(
            listed.len(),
            spec.files.len(),
            "duplicate entries in {}",
            spec.dir
        );
        assert_eq!(
            listed, on_disk,
            "templates/{} and its file list differ",
            spec.dir
        );
    }
}

#[test]
fn render_leaves_no_placeholders() {
    let vars = [
        ("name", "x"),
        ("description", "d"),
        ("terraform_version", "1.0.0"),
    ];
    for t in Template::value_variants() {
        for f in spec(*t).files {
            let out = render(f.contents, &vars);
            assert!(!out.contains('\r'), "{} has CR", f.path);
            for (start, _) in out.match_indices("{{") {
                let rest = &out[start + 2..];
                let key: String = rest.chars().take_while(|c| *c != '}').collect();
                assert!(
                    key.starts_with(' '),
                    "{}: unknown placeholder {{{{{key}}}}}",
                    f.path
                );
            }
        }
    }
}

#[test]
fn render_keeps_pipeline_expressions() {
    let out = render("env: {{name}}-${{ env.name }}", &[("name", "app")]);
    assert_eq!(out, "env: app-${{ env.name }}");
}

#[test]
fn refuses_non_empty_dir_without_force() {
    let dir = std::env::temp_dir().join(format!("aznet-scaffold-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("keep.txt"), "x").unwrap();
    assert!(check_target(&dir, false).is_err());
    assert!(check_target(&dir, true).is_ok());
    fs::remove_dir_all(&dir).unwrap();
}

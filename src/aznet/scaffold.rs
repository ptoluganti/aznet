//! `new`: scaffold a repository from a template compiled into the binary.
//!
//! Templates live under `templates/<template>/`, every file suffixed `.tmpl` so the
//! templates' own `.gitignore`, `.tflint.hcl`, etc. stay inert inside this repo. Adding a
//! template = a directory + a `Template` variant + a `SPEC` arm below; the tests check the
//! file list matches the directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};

use crate::aznet::cli::{parse_project_name, NewArgs, Template};

struct TemplateFile {
    path: &'static str,
    contents: &'static str,
    executable: bool,
}

struct TemplateSpec {
    dir: &'static str,
    files: &'static [TemplateFile],
    next_steps: &'static [&'static str],
}

macro_rules! tpl {
    ($dir:literal, $path:literal) => {
        tpl!($dir, $path, false)
    };
    ($dir:literal, $path:literal, exec) => {
        tpl!($dir, $path, true)
    };
    ($dir:literal, $path:literal, $exec:expr) => {
        TemplateFile {
            path: $path,
            contents: include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/templates/",
                $dir,
                "/",
                $path,
                ".tmpl"
            )),
            executable: $exec,
        }
    };
}

const TERRAFORM_DEPLOYMENT: TemplateSpec = TemplateSpec {
    dir: "terraform-deployment",
    files: &[
        tpl!("terraform-deployment", ".azdo/ci.yml"),
        tpl!("terraform-deployment", ".azdo/cd.yml"),
        tpl!("terraform-deployment", ".husky/commit-msg", exec),
        tpl!("terraform-deployment", ".husky/pre-commit", exec),
        tpl!("terraform-deployment", ".vscode/extensions.json"),
        tpl!("terraform-deployment", ".vscode/settings.json"),
        tpl!("terraform-deployment", "terraform/modules/README.md"),
        tpl!(
            "terraform-deployment",
            "terraform/modules/resource_group/main.tf"
        ),
        tpl!(
            "terraform-deployment",
            "terraform/modules/resource_group/outputs.tf"
        ),
        tpl!(
            "terraform-deployment",
            "terraform/modules/resource_group/variables.tf"
        ),
        tpl!(
            "terraform-deployment",
            "terraform/modules/resource_group/versions.tf"
        ),
        tpl!("terraform-deployment", "terraform/tfvars/dev.tfbackend"),
        tpl!("terraform-deployment", "terraform/tfvars/dev.tfvars"),
        tpl!("terraform-deployment", "terraform/tfvars/test.tfbackend"),
        tpl!("terraform-deployment", "terraform/tfvars/test.tfvars"),
        tpl!("terraform-deployment", "terraform/tfvars/prod.tfbackend"),
        tpl!("terraform-deployment", "terraform/tfvars/prod.tfvars"),
        tpl!("terraform-deployment", "terraform/data.tf"),
        tpl!("terraform-deployment", "terraform/locals.tf"),
        tpl!("terraform-deployment", "terraform/main.tf"),
        tpl!("terraform-deployment", "terraform/outputs.tf"),
        tpl!("terraform-deployment", "terraform/TERRAFORM-DOCS.md"),
        tpl!("terraform-deployment", "terraform/variables.tf"),
        tpl!("terraform-deployment", "terraform/versions.tf"),
        tpl!("terraform-deployment", ".cz.toml"),
        tpl!("terraform-deployment", ".editorconfig"),
        tpl!("terraform-deployment", ".gitattributes"),
        tpl!("terraform-deployment", ".gitignore"),
        tpl!("terraform-deployment", ".pre-commit-config.yaml"),
        tpl!("terraform-deployment", ".terraform-docs.yml"),
        tpl!("terraform-deployment", ".terraform-version"),
        tpl!("terraform-deployment", ".tflint.hcl"),
        tpl!("terraform-deployment", "CHANGELOG.md"),
        tpl!("terraform-deployment", "commitlint.config.js"),
        tpl!("terraform-deployment", "CONTRIBUTING.md"),
        tpl!("terraform-deployment", "package.json"),
        tpl!("terraform-deployment", "README.md"),
        tpl!("terraform-deployment", "VERSION"),
    ],
    next_steps: &[
        "npm install                 # husky git hooks + commitlint",
        "pip install pre-commit      # terraform fmt/validate/tflint/docs hooks",
        "edit terraform/tfvars/*.tfbackend to point at your state storage accounts",
        "create ADO service connections + environments named in .azdo/cd.yml",
    ],
};

fn spec(template: Template) -> &'static TemplateSpec {
    match template {
        Template::TerraformDeployment => &TERRAFORM_DEPLOYMENT,
    }
}

pub fn run(args: NewArgs) -> Result<ExitCode> {
    let spec = spec(args.template);
    let name = match args.name {
        Some(n) => n,
        None => default_name(&args.path)?,
    };
    let description = args
        .description
        .unwrap_or_else(|| format!("Terraform deployment for {name}"));
    let vars = [
        ("name", name.as_str()),
        ("description", description.as_str()),
        ("terraform_version", args.terraform_version.as_str()),
    ];

    check_target(&args.path, args.force)?;

    if args.dry_run {
        for f in spec.files {
            println!("{}", target_path(&args.path, f.path).display());
        }
        return Ok(ExitCode::SUCCESS);
    }

    for f in spec.files {
        let dest = target_path(&args.path, f.path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::write(&dest, render(f.contents, &vars))
            .with_context(|| format!("writing {}", dest.display()))?;
        if f.executable {
            make_executable(&dest)?;
        }
    }

    if args.git {
        let status = Command::new("git")
            .args(["init", "--quiet", "--initial-branch", "main"])
            .current_dir(&args.path)
            .status()
            .context("running git (is it installed and on PATH?)")?;
        if !status.success() {
            bail!("git init failed in {}", args.path.display());
        }
    }

    println!(
        "Created {} '{name}' in {} ({} files)\n\nNext steps:\n  cd {}",
        spec.dir,
        args.path.display(),
        spec.files.len(),
        args.path.display()
    );
    if !args.git {
        println!("  git init -b main");
    }
    for step in spec.next_steps {
        println!("  {step}");
    }
    Ok(ExitCode::SUCCESS)
}

fn default_name(path: &Path) -> Result<String> {
    // absolute(), not canonicalize(): the directory usually doesn't exist yet, and `.` must
    // still resolve to the current directory's name.
    let abs = std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
    let base = abs
        .file_name()
        .and_then(|n| n.to_str())
        .context("cannot derive a project name from the path; pass --name")?;
    parse_project_name(&base.to_ascii_lowercase())
        .map_err(|e| anyhow::anyhow!("{e}; pass --name to set one explicitly"))
}

fn check_target(path: &Path, force: bool) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if !path.is_dir() {
        bail!("{} exists and is not a directory", path.display());
    }
    let non_empty = fs::read_dir(path)
        .with_context(|| format!("reading {}", path.display()))?
        .next()
        .is_some();
    if non_empty && !force {
        bail!(
            "{} is not empty; use --force to write into it (template files are overwritten)",
            path.display()
        );
    }
    Ok(())
}

fn target_path(root: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(root.to_path_buf(), |p, part| p.join(part))
}

/// `{{key}}` substitution. Normalises CRLF (Windows checkouts of this repo) so hook
/// scripts and YAML always land with LF. `${{ ... }}` pipeline expressions have spaces
/// and never match a key.
fn render(contents: &str, vars: &[(&str, &str)]) -> String {
    vars.iter()
        .fold(contents.replace("\r\n", "\n"), |acc, (k, v)| {
            acc.replace(&format!("{{{{{k}}}}}"), v)
        })
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod +x {}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests;

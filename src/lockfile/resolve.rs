//! Copyright (C) Microsoft Corporation.
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.
use glob::glob;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::ops::Deref;
use std::path::PathBuf;

use anyhow::{Context, Result};
use log::debug;
use pyo3::ffi::c_str;
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyDict, PyString, PyTuple};
use url::Url;

use super::{DnfOutput, Lockfile};
use crate::config::Config;
use crate::config::Repository;

const ETC_OS_RELEASE: &str = "/etc/os-release";

impl Lockfile {
    /// Perform dependency resolution on the given package specs
    pub(crate) fn resolve(
        pkg_specs: Vec<String>,
        repositories: &[Repository],
        gpgkeys: Vec<Url>,
        include_etc_os_release: bool,
    ) -> Result<Self> {
        let output = Python::attach(|py| {
            // Resolve is a compiled in python module for resolving dependencies
            let resolve = PyModule::from_code(
                py,
                c_str!(include_str!("resolve.py")),
                c_str!("resolve"),
                c_str!("resolve"),
            )?;
            let base = setup_base(py, repositories, &gpgkeys)?;
            let etc_os_release = ETC_OS_RELEASE.to_string();
            let specs = if include_etc_os_release && !pkg_specs.contains(&etc_os_release) {
                let mut specs = pkg_specs.clone();
                specs.push(etc_os_release.to_string());
                specs
            } else {
                pkg_specs.clone()
            };

            let args = PyTuple::new(py, [base.as_any(), &specs.into_pyobject(py)?])?;
            // Run the resolve function, returning a json string, which we shall deserialize.
            let val: String = resolve.getattr("resolve")?.call1(args)?.extract()?;
            Ok::<_, anyhow::Error>(val)
        })
        .context("Failed to resolve dependencies with dnf")?;

        let results: DnfOutput = serde_json::from_str(&output)?;
        Ok(Lockfile {
            pkg_specs,
            packages: results.packages.into_iter().collect(),
            local_packages: results.local_packages.into_iter().collect(),
            repo_gpg_config: results.repo_gpg_config,
            global_key_specs: gpgkeys,
        })
    }

    /// Create a lockfile from a configuration file
    pub fn resolve_from_config(cfg: &Config) -> Result<Self> {
        Self::resolve(
            cfg.contents.packages.clone(),
            &cfg.contents.repositories,
            cfg.contents.gpgkeys.clone(),
            cfg.contents.os_release,
        )
    }

    /// Read the dependencies of local rpms
    pub fn read_local_rpm_deps(cfg: &Config) -> Result<BTreeSet<String>> {
        let local = cfg
            .contents
            .packages
            .clone()
            .into_iter()
            .filter_map(|spec| {
                if spec.ends_with(".rpm") {
                    match glob(&spec) {
                        Ok(paths) => Some(
                            paths
                                .into_iter()
                                .filter_map(|p| p.ok())
                                .collect::<Vec<PathBuf>>(),
                        ),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            })
            .flatten()
            .collect::<Vec<PathBuf>>();

        let output = Python::attach(|py| {
            // query_local is a compiled in python module for querying local dependencies
            let query = PyModule::from_code(
                py,
                c_str!(include_str!("query_local.py")),
                c_str!("query_local"),
                c_str!("query_local"),
            )?;

            let args = PyTuple::new(py, &[local.into_pyobject(py)?])?;
            // Run the query function, returning a json string, which we shall deserialize.
            let val: String = query.getattr("query_local")?.call1(args)?.extract()?;
            Ok::<_, anyhow::Error>(val)
        })
        .context("Failed to resolve dependencies with dnf")?;

        let results: BTreeSet<String> = serde_json::from_str(&output)?;
        Ok(results)
    }

    /// Create a lockfile by updating any dependencies in the current lockfile
    pub fn resolve_from_previous(&self, cfg: &Config) -> Result<Self> {
        let requires = cfg
            .contents
            .packages
            .clone()
            .into_iter()
            .filter(|spec| !spec.ends_with(".rpm"))
            .chain(
                self.local_packages
                    .iter()
                    .flat_map(|pkg| pkg.requires.clone()),
            )
            // dnf is not aware of rpmlib() requirements that the RPMs may have, so we need to filter them out
            // similar to tdnf: https://github.com/vmware/tdnf/blob/ed235f71ec6d477c8934b82ea12d983c0a8c60d8/client/resolve.c#L508
            .filter(|requires| !requires.starts_with("rpmlib("))
            .collect::<Vec<_>>();

        let mut lockfile = Self::resolve(
            requires,
            &cfg.contents.repositories,
            cfg.contents.gpgkeys.clone(),
            cfg.contents.os_release,
        )?;
        lockfile.local_packages.clone_from(&self.local_packages);
        lockfile.pkg_specs.clone_from(&cfg.contents.packages);
        Ok(lockfile)
    }
}

/// A wrapper around the dnf.Base object which ensures that plugins are unloaded
pub(crate) struct Base<'a> {
    value: Bound<'a, PyAny>,
}

impl<'a> Deref for Base<'a> {
    type Target = Bound<'a, PyAny>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Drop for Base<'_> {
    fn drop(&mut self) {
        // Unload plugins as otherwise dnf can raise an error when we call setup_base again
        // self.value.call_method0("unload_plugins").unwrap();
        // To support Azure Linx (Mariner), don't use unload_plugins
        // as it's not present in dnf 4.8.0
        self.value
            .getattr("_plugins")
            .unwrap()
            .call_method0("_unload")
            .unwrap();
    }
}

fn home_dir() -> Option<PathBuf> {
    // The home_dir bugs on windows are irrelevant as rpmoci is linux only
    #![allow(deprecated)]
    std::env::home_dir()
}

/// Return a directory to use for caching dnf data
fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME")
        .and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        })
        .or_else(|| home_dir().map(|p| p.join(".cache")))
        .map(|p| p.join("rpmoci"))
}

/// Initialize the dnf.Base object with the repositories configured in the rpmoci.toml
/// The Base object also initializes and configures any system defined plugins
pub(crate) fn setup_base<'a>(
    py: Python<'a>,
    repositories: &[Repository],
    gpgkeys: &[Url],
) -> Result<Base<'a>> {
    let dnf = PyModule::import(py, "dnf").context("Failed to import dnf")?;
    let base = dnf
        .getattr("Base")?
        .call0()
        .context("Failed to create base")?;
    let conf = base.getattr("conf").context("Failed to get conf")?;

    // To support running in a user namespace override the cache and log directories
    // as dnf will choose directories only root can write to.
    if let Some(cache_dir) = cache_dir() {
        conf.setattr("cachedir", cache_dir.as_os_str())
            .context("Failed to set cachedir")?;
        conf.setattr("logdir", cache_dir.as_os_str())
            .context("Failed to set logdir")?;
    }

    base.call_method0("init_plugins")?;
    base.call_method0("pre_configure_plugins")?;

    // If any repositories were specified by repoid, enable them first
    let existing_repos = repositories
        .iter()
        .filter_map(|repo| {
            if let Repository::Id(repoid) = repo {
                Some(repoid)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if !existing_repos.is_empty() {
        // Load system repos
        base.call_method0("read_all_repos")?;

        // Disable all repos
        let repos = base.getattr("repos")?;
        repos.call_method0("all")?.call_method0("disable")?;
        // Enable the configured ones
        for repo_id in existing_repos {
            repos
                .get_item(repo_id)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Repository not found in system config, repoid: '{}'",
                        repo_id
                    )
                })?
                .call_method0("enable")?;
        }
    }

    // Now configure any repositories defined by URL/definition
    for repo in repositories {
        let args = PyTuple::new(
            py,
            [
                PyString::new(py, &repo.repo_id())
                    .into_pyobject(py)?
                    .as_any(),
                conf.as_any(),
            ],
        )?;
        match &repo {
            Repository::Url(url) => {
                base.getattr("repos")?.call_method(
                    "add_new_repo",
                    args,
                    Some(&repo_kwargs(
                        url,
                        &HashMap::new(),
                        gpgkeys,
                        repo_username(&repo.repo_id()),
                        repo_password(&repo.repo_id()),
                        py,
                    )?),
                )?;
            }
            Repository::Id(_) => {}
            Repository::Definition(definition) => {
                base.getattr("repos")?.call_method(
                    "add_new_repo",
                    args,
                    Some(&repo_kwargs(
                        &definition.url,
                        &definition.options,
                        gpgkeys,
                        repo_username(&repo.repo_id()),
                        repo_password(&repo.repo_id()),
                        py,
                    )?),
                )?;
            }
        }
    }

    base.call_method0("configure_plugins")?;

    base.call_method(
        "fill_sack",
        (),
        Some(&[("load_system_repo", false)].into_py_dict(py)?),
    )?;
    Ok(Base { value: base })
}

fn default_repo_options() -> HashMap<String, String> {
    let mut options = HashMap::new();
    options.insert("gpgcheck".to_string(), "True".to_string());
    options.insert("sslverify".to_string(), "True".to_string());
    options
}

pub(crate) fn repo_kwargs<'p>(
    repo_url: &Url,
    repo_options: &HashMap<String, String>,
    gpgkeys: &[Url],
    username: Option<String>,
    password: Option<String>,
    py: Python<'p>,
) -> Result<Bound<'p, PyDict>, pyo3::PyErr> {
    let mut kwargs = Vec::new();
    let mut default_repo_options = default_repo_options();

    // Global keys need to be merged with the repo definition keys in case
    // they are needed for repo metadata verification
    let global_gpgkeys = gpgkeys
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    // If the repo definition specified gpgkey, this option won't be used
    default_repo_options.insert("gpgkey".to_string(), global_gpgkeys.clone());

    let val = [PyString::new(py, repo_url.as_ref())].into_pyobject(py)?;
    kwargs.push(("baseurl".to_string(), val.into_any()));

    for (key, val) in repo_options {
        // If the repo definition specified gpgkey, add the global keys to it
        let val = if key == "gpgkey" {
            (val.to_owned() + " " + &global_gpgkeys).into_pyobject(py)
        } else {
            val.into_pyobject(py)
        }?;
        kwargs.push((key.to_string(), val.into_any()));
        default_repo_options.remove(key);
    }

    for (key, val) in &default_repo_options {
        kwargs.push((key.to_string(), val.into_pyobject(py)?.into_any()));
    }

    // If auth is configured via envs, add that here
    if let Some(username) = username {
        debug!("using username from environment");
        kwargs.push((
            "username".to_string(),
            username.into_pyobject(py)?.into_any(),
        ));
    }
    if let Some(password) = password {
        debug!("using password from environment");
        kwargs.push((
            "password".to_string(),
            password.into_pyobject(py)?.into_any(),
        ));
    }

    kwargs.into_py_dict(py)
}

fn repo_username(repo_id: &str) -> Option<String> {
    env::var(format!(
        "RPMOCI_{}_HTTP_USERNAME",
        repo_id.to_ascii_uppercase()
    ))
    .ok()
}

fn repo_password(repo_id: &str) -> Option<String> {
    env::var(format!(
        "RPMOCI_{}_HTTP_PASSWORD",
        repo_id.to_ascii_uppercase()
    ))
    .ok()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr, sync::Mutex};

    use pyo3::ffi::c_str;
    use pyo3::prelude::*;
    use url::Url;

    use crate::{
        config::{Repository, RepositoryDefinition},
        lockfile::Lockfile,
    };

    /// Run `check` (a Python function taking the resolve module) against the real resolve.py.
    /// hawkey packages can't be constructed standalone, so the checks use stand-in objects
    /// exposing the attributes `deduplicate_packages` reads.
    static DEDUP_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn run_dedup_check(check: &str) -> PyResult<()> {
        let _guard = DEDUP_TEST_LOCK.lock().unwrap();
        Python::attach(|py| {
            let resolve = PyModule::from_code(
                py,
                c_str!(include_str!("resolve.py")),
                c_str!("resolve"),
                c_str!("resolve"),
            )?;
            let helpers = PyModule::from_code(
                py,
                c_str!(
                    r#"
from pathlib import Path
from types import SimpleNamespace
import tempfile
import dnf
import hawkey


class Repo:
    def __init__(self):
        self.pkgdir = str(Path(tempfile.gettempdir()) / "rpmoci-dedup-cache")
        self.gpgcheck = False
        self.gpgkey = []


def pkg(name="foo", epoch=0, version="1.0", release="1", arch="x86_64",
        repoid="virtual", algo=hawkey.CHKSUM_SHA256, digest=b"\x01" * 32,
        location="foo.rpm", data=b"rpm bytes", repo=None):
    repo = repo or Repo()
    package = SimpleNamespace(
        name=name, epoch=epoch, version=version, release=release,
        arch=arch, repoid=repoid, chksum=(algo, digest), repo=repo,
        location=location, data=data,
    )
    package.evr = f"{epoch}:{version}-{release}"
    package.localPkg = lambda: str(Path(package.repo.pkgdir) / Path(package.location).name)
    return package


class Base:
    sack = object()

    def __init__(self, fail=False, cacheonly=False):
        self.calls = []
        self.fail = fail
        self.conf = SimpleNamespace(cacheonly=cacheonly)

    def download_packages(self, packages):
        for package in packages:
            self.calls.append((package, package.repo.pkgdir))
            if self.fail:
                raise OSError("offline download failure")
            path = Path(package.localPkg())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(package.data)


def raises(resolve, pkgs, base=None):
    try:
        resolve.deduplicate_packages(base if base is not None else Base(), pkgs)
    except dnf.exceptions.Error as e:
        return str(e)
    raise AssertionError("expected a DNF error")


def identical(resolve):
    a = pkg(location="z/foo.rpm")
    b = pkg(location="a/foo.rpm")
    base = Base()
    assert resolve.deduplicate_packages(base, [a, b]) == [b]
    assert base.calls == [], "matching strong checksums should not download"


# SHA-1 and SHA-256 advertisements need byte comparison before deduplication.
def cross_algorithm_identical(resolve):
    repo = Repo()
    sha1 = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20,
               location="upstream/foo.rpm", repo=repo)
    sha256 = pkg(algo=hawkey.CHKSUM_SHA256, location="z-archive/foo.rpm", repo=repo)
    base = Base()
    assert resolve.deduplicate_packages(base, [sha1, sha256]) == [sha256]
    assert len(base.calls) == 2
    assert base.calls[0][1] != base.calls[1][1], "same-basename downloads collided"
    assert sha1.repo.pkgdir == sha256.repo.pkgdir == str(Path(tempfile.gettempdir()) / "rpmoci-dedup-cache")


def matching_sha256_preferred(resolve):
    repo = Repo()
    sha1 = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20,
               location="a-archive/foo.rpm", repo=repo)
    sha256 = pkg(algo=hawkey.CHKSUM_SHA256, location="archive/foo.rpm", repo=repo)
    base = Base()
    assert resolve.deduplicate_packages(base, [sha256, sha1]) == [sha256]
    assert len(base.calls) == 2


# A SHA-1-only package still needs a calculated digest in the lockfile.
def sha1_checksum_serialized_as_sha256(resolve):
    repo = Repo()
    sha1 = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20,
               location="a-archive/foo.rpm", repo=repo)
    base = Base()
    resolve.get_packages = lambda base, spec: [sha1]

    class Goal:
        def __init__(self, sack):
            self.installed = []

        def install(self, package):
            self.installed.append(package)

        def run(self, ignore_weak_deps=True):
            return True

        def list_installs(self):
            return [sha1]

    original_goal = resolve.hawkey.Goal
    resolve.hawkey.Goal = Goal
    try:
        output = __import__("json").loads(resolve.resolve(base, ["foo"]))
        checksum = output["packages"][0]["checksum"]
        assert checksum == {
            "algorithm": "sha256",
            "checksum": __import__("hashlib").sha256(sha1.data).hexdigest(),
        }, output
        assert len(base.calls) == 1
    finally:
        resolve.hawkey.Goal = original_goal


def conflicting_bytes(resolve):
    repo = Repo()
    a = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20,
            location="upstream/foo.rpm", data=b"first", repo=repo)
    b = pkg(algo=hawkey.CHKSUM_SHA256, location="archive/foo.rpm", data=b"second", repo=repo)
    msg = raises(resolve, [a, b])
    assert "foo-0:1.0-1.x86_64" in msg and "'virtual'" in msg, msg
    assert "upstream/foo.rpm" in msg and "archive/foo.rpm" in msg, msg
    assert "sha1:" + "01" * 20 in msg and "sha256:" + "01" * 32 in msg, msg
    assert __import__("hashlib").sha256(b"first").hexdigest() in msg, msg
    assert __import__("hashlib").sha256(b"second").hexdigest() in msg, msg


def weak_checksum_requires_hash(resolve):
    repo = Repo()
    a = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20, repo=repo)
    b = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20, repo=repo)
    base = Base()
    assert resolve.deduplicate_packages(base, [a, b]) == [a]
    assert len(base.calls) == 2


def download_failure(resolve):
    repo = Repo()
    a = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20,
            location="upstream/foo.rpm", repo=repo)
    b = pkg(algo=hawkey.CHKSUM_SHA256, location="archive/foo.rpm", repo=repo)
    original_pkgdir = repo.pkgdir
    msg = raises(resolve, [a, b], Base(fail=True))
    assert "download or SHA-256 verification failed" in msg, msg
    assert "upstream/foo.rpm" in msg and "archive/foo.rpm" in msg, msg
    assert "calculated_sha256=unavailable" in msg, msg
    assert repo.pkgdir == original_pkgdir

    class MissingFile(Base):
        def download_packages(self, packages):
            pass

    msg = raises(resolve, [a, b], MissingFile())
    assert "RPM not found" in msg, msg
    assert repo.pkgdir == original_pkgdir

    real_open = open
    def unreadable(*args, **kwargs):
        raise OSError("unreadable RPM")
    resolve.open = unreadable
    try:
        msg = raises(resolve, [a, b])
        assert "unreadable RPM" in msg, msg
        assert repo.pkgdir == original_pkgdir
    finally:
        del resolve.open


def cacheonly_uses_cached_files(resolve):
    with tempfile.TemporaryDirectory() as cachedir:
        a = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20,
                location="upstream/foo.rpm", data=b"same")
        b = pkg(algo=hawkey.CHKSUM_SHA256, location="archive/foo.rpm", data=b"same")
        a.repo.pkgdir = str(Path(cachedir) / "first")
        b.repo.pkgdir = str(Path(cachedir) / "second")
        for package in (a, b):
            path = Path(package.localPkg())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(package.data)
        a.verifyLocalPkg = lambda: True
        b.verifyLocalPkg = lambda: True
        base = Base(cacheonly=True)
        assert resolve.deduplicate_packages(base, [a, b]) == [b]
        assert base.calls == []
        assert b.repo.pkgdir == str(Path(cachedir) / "second")

        repeated = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20, data=b"same")
        repeated.repo.pkgdir = str(Path(cachedir) / "repeated")
        repeated_path = Path(repeated.localPkg())
        repeated_path.parent.mkdir(parents=True, exist_ok=True)
        repeated_path.write_bytes(repeated.data)
        repeated.verifyLocalPkg = lambda: True
        base = Base(cacheonly=True)
        assert resolve.deduplicate_packages(base, [repeated, repeated]) == [repeated]
        assert base.calls == []

        other = pkg(algo=hawkey.CHKSUM_SHA256, location="other/foo.rpm", data=b"same")
        other.repo.pkgdir = repeated.repo.pkgdir
        other.verifyLocalPkg = lambda: True
        assert "share a cached RPM path" in raises(
            resolve, [repeated, other], Base(cacheonly=True)
        )


def cacheonly_invalid_checksum(resolve):
    with tempfile.TemporaryDirectory() as cachedir:
        a = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20, data=b"cached")
        b = pkg(algo=hawkey.CHKSUM_SHA256, data=b"cached")
        for index, package in enumerate((a, b)):
            package.repo.pkgdir = str(Path(cachedir) / str(index))
            path = Path(package.localPkg())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(package.data)
        a.verifyLocalPkg = lambda: True
        b.verifyLocalPkg = lambda: False
        msg = raises(resolve, [a, b], Base(cacheonly=True))
        assert "cached RPM checksum mismatch" in msg, msg
        assert "foo.rpm" in msg, msg


def distinct_identity(resolve):
    repo = Repo()
    local = pkg(repoid=hawkey.CMDLINE_REPO_NAME, digest=None)
    pkgs = [
        pkg(repo=repo), pkg(name="bar", repo=repo), pkg(version="1.1", repo=repo),
        pkg(release="2", repo=repo), pkg(epoch=1, repo=repo), pkg(arch="noarch", repo=repo),
        pkg(repoid="other", repo=repo), local, pkg(repoid=hawkey.CMDLINE_REPO_NAME, digest=None),
    ]
    base = Base()
    assert resolve.deduplicate_packages(base, pkgs) == pkgs
    assert base.calls == []


def failure_before_goal(resolve):
    repo = Repo()
    first = pkg(algo=hawkey.CHKSUM_SHA1, digest=b"\x01" * 20, data=b"first", repo=repo)
    second = pkg(algo=hawkey.CHKSUM_SHA256, data=b"second", repo=repo)
    resolve.get_packages = lambda base, spec: [first, second]
    goal_calls = []

    class Goal:
        def __init__(self, sack):
            goal_calls.append("created")

    real_hawkey = resolve.hawkey
    resolve.hawkey = SimpleNamespace(
        Goal=Goal, CMDLINE_REPO_NAME=real_hawkey.CMDLINE_REPO_NAME,
        CHKSUM_MD5=real_hawkey.CHKSUM_MD5, CHKSUM_SHA1=real_hawkey.CHKSUM_SHA1,
        CHKSUM_SHA256=real_hawkey.CHKSUM_SHA256, CHKSUM_SHA384=real_hawkey.CHKSUM_SHA384,
        CHKSUM_SHA512=real_hawkey.CHKSUM_SHA512,
    )
    try:
        try:
            resolve.resolve(Base(), ["foo"])
        except dnf.exceptions.Error:
            pass
        else:
            raise AssertionError("expected conflicting candidates to fail")
        assert goal_calls == [], "solver goal was constructed before duplicate verification"
    finally:
        resolve.hawkey = real_hawkey
"#
                ),
                c_str!("helpers"),
                c_str!("helpers"),
            )?;
            helpers.getattr(check)?.call1((resolve,))?;
            Ok(())
        })
    }

    #[test]
    fn test_dedup_identical_checksums() {
        run_dedup_check("identical").unwrap();
    }

    #[test]
    fn test_dedup_cross_algorithm_identical_bytes() {
        run_dedup_check("cross_algorithm_identical").unwrap();
        run_dedup_check("matching_sha256_preferred").unwrap();
        run_dedup_check("sha1_checksum_serialized_as_sha256").unwrap();
    }

    #[test]
    fn test_dedup_conflicting_bytes_before_goal() {
        run_dedup_check("conflicting_bytes").unwrap();
        run_dedup_check("failure_before_goal").unwrap();
    }

    #[test]
    fn test_dedup_weak_checksum_requires_hash() {
        run_dedup_check("weak_checksum_requires_hash").unwrap();
    }

    #[test]
    fn test_dedup_download_failure() {
        run_dedup_check("download_failure").unwrap();
    }

    #[test]
    fn test_dedup_cacheonly_uses_cached_files() {
        run_dedup_check("cacheonly_uses_cached_files").unwrap();
        run_dedup_check("cacheonly_invalid_checksum").unwrap();
    }

    #[test]
    fn test_dedup_keeps_distinct_identities() {
        run_dedup_check("distinct_identity").unwrap();
    }

    /// Reproduce a virtual repo exposing `foo-1.0-1.x86_64` twice (upstream + archive members)
    /// using real DNF/hawkey loaded from local repo metadata, then run `resolve`.
    fn resolve_virtual_repo_duplicates(second_digest: &str) -> PyResult<String> {
        let _guard = DEDUP_TEST_LOCK.lock().unwrap();
        Python::attach(|py| {
            let resolve = PyModule::from_code(
                py,
                c_str!(include_str!("resolve.py")),
                c_str!("resolve"),
                c_str!("resolve"),
            )?;
            let helpers = PyModule::from_code(
                py,
                c_str!(
                    r#"
import tempfile
from types import SimpleNamespace
from pathlib import Path

import dnf
import dnf.package
import dnf.sack
import hawkey

PACKAGE = """<package type="rpm"><name>foo</name><arch>{arch}</arch>
<version epoch="0" ver="1.0" rel="1"/>
<checksum type="{checksum_type}" pkgid="YES">{checksum}</checksum>
<summary>foo</summary><description>foo</description><packager>test</packager><url/>
<time file="0" build="0"/><size package="{size}" installed="1" archive="1"/>
<location href="{location}"/>
<format><rpm:license>MIT</rpm:license><rpm:group>Unspecified</rpm:group>
<rpm:header-range start="0" end="0"/>
<rpm:provides><rpm:entry name="foo" flags="EQ" epoch="0" ver="1.0" rel="1"/></rpm:provides>
</format></package>"""


def run(resolve, second_digest):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "upstream").mkdir()
        (root / "archive").mkdir()
        first_bytes = b"identical bytes"
        second_bytes = b"identical bytes" if second_digest == "identical" else second_digest.encode()
        (root / "upstream/foo.rpm").write_bytes(first_bytes)
        (root / "archive/foo.rpm").write_bytes(second_bytes)
        base = dnf.Base()
        arch = base.conf.basearch
        import hashlib
        checksum = hashlib.sha256(first_bytes).hexdigest()
        entries = PACKAGE.format(
            arch=arch,
            checksum_type="sha1",
            checksum=hashlib.sha1(first_bytes).hexdigest(),
            location="upstream/foo.rpm",
            size=len(first_bytes),
        )
        second_checksum = hashlib.sha256(second_bytes).hexdigest()
        entries += PACKAGE.format(
            arch=arch,
            checksum_type="sha256",
            checksum=second_checksum,
            location="archive/foo.rpm",
            size=len(second_bytes),
        )
        (root / "primary.xml").write_text(
            '<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common" '
            'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">'
            + entries + "</metadata>"
        )
        (root / "repomd.xml").write_text(
            '<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo">'
            '<data type="primary"><location href="primary.xml"/></data></repomd>'
        )
        base.repos.add_new_repo("virtual", base.conf, baseurl=[root.as_uri()], gpgcheck=False)
        sack = dnf.sack.Sack(
            pkgcls=dnf.package.Package, pkginitval=base, arch=arch, cachedir=str(root / "cache")
        )
        repo = hawkey.Repo("virtual")
        repo.primary_fn = str(root / "primary.xml")
        repo.repomd_fn = str(root / "repomd.xml")
        sack.load_repo(repo, build_cache=False)
        base._sack = sack
        base.repos["virtual"].gpgcheck = False
        candidates = resolve.get_packages(base, "foo")
        assert len(candidates) == 2
        assert candidates[0].repoid == candidates[1].repoid == "virtual"
        return resolve.resolve(base, ["foo"])
"#
                ),
                c_str!("helpers"),
                c_str!("helpers"),
            )?;
            helpers
                .getattr("run")?
                .call1((resolve, second_digest))?
                .extract()
        })
    }

    #[test]
    fn test_dnf_virtual_repo_identical_duplicates_resolve() {
        let output: serde_json::Value =
            serde_json::from_str(&resolve_virtual_repo_duplicates("identical").unwrap()).unwrap();
        let packages = output["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0]["name"], "foo");
        assert_eq!(packages[0]["checksum"]["algorithm"], "sha256");
        assert_eq!(
            packages[0]["checksum"]["checksum"],
            "8ca5bfb553e7ce32d7543bac5f91cdc3e28d650106da4e244c0eeb5e3a71ea64"
        );
    }

    #[test]
    fn test_dnf_virtual_repo_conflicting_duplicates_error() {
        let err = resolve_virtual_repo_duplicates("different bytes").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("foo-0:1.0-1."), "{msg}");
        assert!(msg.contains("upstream/foo.rpm"), "{msg}");
        assert!(msg.contains("archive/foo.rpm"), "{msg}");
        assert!(msg.contains("calculated_sha256="), "{msg}");
        assert!(msg.contains("checksum=sha256:"), "{msg}");
    }

    #[test]
    fn test_dedup_solver_errors_are_not_caught() {
        let _guard = DEDUP_TEST_LOCK.lock().unwrap();
        Python::attach(|py| {
            let resolve = PyModule::from_code(
                py,
                c_str!(include_str!("resolve.py")),
                c_str!("resolve"),
                c_str!("resolve"),
            )
            .unwrap();
            let helpers = PyModule::from_code(
                py,
                c_str!(
                    r#"
import dnf
from types import SimpleNamespace

def check(resolve):
    class Base:
        class Sack:
            pass
        sack = Sack()

    class Goal:
        def __init__(self, sack):
            pass
        def install(self, pkg):
            pass
        def run(self, ignore_weak_deps):
            return False
        def problem_rules(self):
            return []

    class Package:
        name, epoch, version, release, arch = "foo", 0, "1", "1", "x86_64"
        repoid, chksum = "test", (2, b"\x01" * 32)

    resolve.get_packages = lambda base, spec: [Package()]
    resolve.hawkey = SimpleNamespace(Goal=Goal, CMDLINE_REPO_NAME=resolve.hawkey.CMDLINE_REPO_NAME)
    try:
        resolve.resolve(Base(), ["requested"])
    except dnf.exceptions.DepsolveError:
        return
    raise AssertionError("DNF dependency-resolution error was suppressed")
"#
                ),
                c_str!("helpers"),
                c_str!("helpers"),
            )
            .unwrap();
            helpers.getattr("check").unwrap().call1((resolve,)).unwrap();
        });
    }

    #[test]
    fn test_weak_deps() {
        // prce2-tools in mariner recommends pcre2-docs. use this to test weak dep behaviour
        let mut options = HashMap::new();
        options.insert("gpgcheck".to_string(), "True".to_string());
        options.insert("gpgkey".to_string(), "https://raw.githubusercontent.com/microsoft/CBL-Mariner/2.0/SPECS/mariner-repos/MICROSOFT-RPM-GPG-KEY,https://packages.microsoft.com/keys/microsoft.asc".to_string());

        let mariner_repository = Repository::Definition(RepositoryDefinition {
            id: Some("marinertest".to_string()),
            url: Url::from_str("https://packages.microsoft.com/cbl-mariner/2.0/prod/base/x86_64")
                .unwrap(),
            options,
        });
        let repositories = vec![mariner_repository];

        let lock = Lockfile::resolve(
            vec!["pcre2-tools".to_string()],
            &repositories,
            Vec::new(),
            true,
        )
        .unwrap();
        assert!(!lock.packages.iter().any(|p| p.name == "pcre2-doc"));
    }
}

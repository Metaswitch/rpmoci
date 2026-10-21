"""A dependency resolver for rpmoci"""

# Copyright (C) Microsoft Corporation.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from dnf.i18n import _
import dnf
import hawkey
import itertools
import json
import glob
import hashlib
import os
import tempfile


def deduplicate_packages(base, packages):
    """Remove byte-identical candidates with the same identity from one repository."""
    groups = {}
    ordered = []
    for pkg in packages:
        # Keep local RPMs out of repository candidate groups.
        if pkg.repoid == hawkey.CMDLINE_REPO_NAME:
            ordered.append([pkg])
            continue

        identity = (pkg.repoid, pkg.name, pkg.epoch, pkg.version, pkg.release, pkg.arch)
        group = groups.get(identity)
        if group is None:
            group = groups[identity] = []
            ordered.append(group)
        if not any(pkg is candidate for candidate in group):
            group.append(pkg)

    unique = []
    for group in ordered:
        if len(group) == 1:
            unique.append(group[0])
            continue

        # Matching strong checksums prove identity without downloading RPMs.
        checksums = [_strong_checksum_identity(pkg.chksum) for pkg in group]
        representative = min(
            group,
            key=lambda pkg: (
                _checksum_algorithm(pkg.chksum[0]) != "sha256",
                pkg.location,
                _checksum_description(pkg.chksum),
            ),
        )
        if checksums[0] is not None and all(c == checksums[0] for c in checksums):
            unique.append(representative)
            continue

        if base.conf.cacheonly:
            cached_paths = [os.path.realpath(pkg.localPkg()) for pkg in group]
            if len(set(cached_paths)) != len(cached_paths):
                raise dnf.exceptions.Error(
                    _candidate_error(group, "candidates share a cached RPM path in cache-only mode")
                )

        # Weak or mixed checksums are verified by comparing downloaded RPM bytes.
        sha256s = []
        for pkg in group:
            try:
                sha256s.append(_download_sha256(base, pkg))
            except Exception as exc:
                unavailable = sha256s + [None] * (len(group) - len(sha256s))
                raise dnf.exceptions.Error(
                    _candidate_error(
                        group,
                        f"download or SHA-256 verification failed for {pkg.location!r}: {exc}",
                        unavailable,
                    )
                ) from exc
        if len(set(sha256s)) != 1:
            raise dnf.exceptions.Error(
                _candidate_error(group, "RPM bytes differ", sha256s)
            )
        unique.append(representative)

    return unique


def _download_sha256(base, pkg):
    original_pkgdir = pkg.repo.pkgdir
    temp_pkgdir = None
    try:
        if base.conf.cacheonly:
            rpm_path = pkg.localPkg()
            if not os.path.isfile(rpm_path):
                raise FileNotFoundError(f"cached RPM not found at {rpm_path!r}")
            if pkg.verifyLocalPkg() is not True:
                raise dnf.exceptions.Error(f"cached RPM checksum mismatch at {rpm_path!r}")
        else:
            temp_pkgdir = tempfile.TemporaryDirectory(prefix="rpmoci-dedup-")
            pkg.repo.pkgdir = temp_pkgdir.name
            base.download_packages([pkg])
            rpm_path = pkg.localPkg()
        if not os.path.isfile(rpm_path):
            raise FileNotFoundError(f"RPM not found at {rpm_path!r}")
        hasher = hashlib.sha256()
        with open(rpm_path, "rb") as rpm:
            while True:
                data = rpm.read(65536)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()
    except Exception as exc:
        raise dnf.exceptions.Error(str(exc)) from exc
    finally:
        pkg.repo.pkgdir = original_pkgdir
        if temp_pkgdir is not None:
            temp_pkgdir.cleanup()


def _candidate_error(group, reason, sha256s=None):
    first = group[0]
    identity = f"{first.name}-{first.epoch}:{first.version}-{first.release}.{first.arch}"
    details = []
    for index, pkg in enumerate(group):
        detail = (
            f"location={pkg.location!r}, "
            f"checksum={_checksum_description(pkg.chksum)}"
        )
        if sha256s is not None:
            detail += f", calculated_sha256={sha256s[index] or 'unavailable'}"
        details.append(detail)
    return (
        f"Cannot deduplicate RPM candidates for {identity} in repository "
        f"{first.repoid!r}: {reason}; " + "; ".join(details)
    )


def _checksum_identity(chksum):
    if not chksum or not chksum[1]:
        return None

    algorithm = _checksum_algorithm(chksum[0])
    return (algorithm, chksum[1]) if algorithm else None


def _strong_checksum_identity(chksum):
    identity = _checksum_identity(chksum)
    if identity is None or identity[0] not in ("sha256", "sha384", "sha512"):
        return None
    if len(identity[1]) != hashlib.new(identity[0]).digest_size:
        return None
    return identity


def _checksum_description(chksum):
    if not chksum or not chksum[1]:
        return "checksum unavailable"

    algorithm = _checksum_algorithm(chksum[0])
    if algorithm is None:
        algorithm = f"unknown algorithm {chksum[0]}"
    digest = chksum[1].hex() if hasattr(chksum[1], "hex") else str(chksum[1])
    return f"{algorithm}:{digest}"


def _checksum_algorithm(checksum_type):
    return {
        hawkey.CHKSUM_MD5: "md5",  # Devskim: ignore DS126858
        hawkey.CHKSUM_SHA1: "sha1",  # Devskim: ignore DS126858
        hawkey.CHKSUM_SHA256: "sha256",
        hawkey.CHKSUM_SHA384: "sha384",
        hawkey.CHKSUM_SHA512: "sha512",
    }.get(checksum_type)


def resolve(base, packages):
    """Resolves packages.
    base needs to be a dnf.Base() object that has had repos configured and fill_sack called.
    packages is an array of requested package specifications"""
    pkgs = itertools.chain.from_iterable(
        [get_packages(base, pkg_spec) for pkg_spec in packages]
    )
    pkgs = deduplicate_packages(base, pkgs)
    goal = hawkey.Goal(base.sack)
    for pkg in pkgs:
        goal.install(pkg)

    if not goal.run(ignore_weak_deps=True):
        msg = dnf.util._format_resolve_problems(goal.problem_rules())
        raise dnf.exceptions.DepsolveError(msg)

    resolved_pkgs = goal.list_installs()
    # DNF may return another candidate from a virtual repo; use its preferred checksum metadata.
    repo_gpg_info = {}
    # Collect GPG keys for this repository
    for pkg in resolved_pkgs:
        if pkg.repoid != hawkey.CMDLINE_REPO_NAME and pkg.repoid not in repo_gpg_info:
            repo_gpg_info[pkg.repoid] = {
                "gpgcheck": pkg.repo.gpgcheck,
                "keys": retrieve_keys(pkg.repo),
            }

    output = {
        "packages": [
            pkg_to_dict(base, pkg, pkg.chksum)
            for pkg in resolved_pkgs
            if pkg.repoid != hawkey.CMDLINE_REPO_NAME
        ],
        "local_packages": [
            {
                "name": pkg.name,
                "requires": [str(requires) for requires in pkg.requires],
            }
            for pkg in resolved_pkgs
            if pkg.repoid == hawkey.CMDLINE_REPO_NAME
        ],
        "repo_gpg_config": repo_gpg_info,
    }
    return json.dumps(output, indent=2)


def get_packages(base, pkg_spec):
    """Find packages matching given spec."""
    if pkg_spec.endswith(".rpm"):
        # Local RPM file
        pkgfilter = base.add_remote_rpms(glob.glob(pkg_spec))
        query = base.sack.query().filterm(pkg=pkgfilter)
    else:
        subj = dnf.subject.Subject(pkg_spec)
        query = subj.get_best_query(base.sack)
        query = query.available()
        query = query.filterm(
            latest_per_arch_by_priority=True, arch=[base.conf.basearch, "noarch"]
        )

    pkgs = query.run()
    if not pkgs:
        msg = "No packages available for spec '%s'" % pkg_spec
        raise dnf.exceptions.DepsolveError(msg)
    return pkgs


def retrieve_keys(repo):
    raw_keys = []
    if repo.gpgcheck:
        for keyurl in repo.gpgkey:
            for key in dnf.crypto.retrieve(keyurl, repo):
                raw_keys.append(key.raw_key.decode())
    return raw_keys


def pkg_to_dict(base, pkg, chksum):
    if _checksum_algorithm(chksum[0]) == "sha256":
        checksum = chksum_to_dict(chksum)
    elif pkg.repoid == hawkey.CMDLINE_REPO_NAME:
        checksum = chksum_to_dict(chksum)
    else:
        checksum = {
            "algorithm": "sha256",
            "checksum": _download_sha256(base, pkg),
        }
    return {
        "name": pkg.name,
        "evr": pkg.evr,
        "checksum": checksum,
        "repoid": pkg.repoid,
        "arch": pkg.arch,
    }


def chksum_to_dict(chksum):
    algo = _checksum_algorithm(chksum[0])
    if algo is None:
        raise dnf.exceptions.Error("Unknown checksum value %d" % chksum[0])
    return {"algorithm": algo, "checksum": chksum[1].hex()}

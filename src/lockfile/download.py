"""RPM downloader module."""

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
import shutil
import sys
from dnf.i18n import _
import dnf
from dnf.cli.progress import MultiFileProgressMeter
import hashlib
import hawkey


class Package:
    """Store information about RPM packages."""

    def __init__(self, name, evr, algo, checksum, arch) -> None:
        self.name = name
        self.evr = evr
        self.algo = algo
        self.checksum = checksum
        self.arch = arch
        self.package = None  # dnf.package.Package
        self.checked = False


def download(base, packages, directory):
    """Downloads packages.
    Parameters:
    - base needs to be a dnf.Base() object that has had repos configured and fill_sack called.
    - packages is a list of [name, evr, checksum algorithm, checksum, arch] lists, of requested package specifications.
    - directory, where to copy the RPMs to.
    """
    # Convert input to our own Package type for convenience.
    pkgs = [Package(p[0], p[1], p[2], p[3], p[4]) for p in packages]

    # Fill in DNF package info, and take a note of whichever checksums already match.
    for p in pkgs:
        get_package(base, p)

    # Download the RPMs.
    base.download_packages(
        (p.package for p in pkgs), MultiFileProgressMeter(fo=sys.stdout)
    )

    # Download each RPM. If we haven't been able to verify the checksum yet because we got a different checksum
    # algorithm than we had when we originally resolved the RPM, then verify it now by hashing the file.
    for p in pkgs:
        if not p.checked:
            # Checksum types must not have matched, hash the RPM now.
            hasher = hashlib.new(p.algo)
            with open(p.package.localPkg(), "rb") as f:
                while True:
                    data = f.read(65536)
                    if not data:
                        break
                    hasher.update(data)

            checksum = hasher.hexdigest()
            if p.checksum != checksum:
                msg = (
                    "Package checksum didn't match: "
                    f"Name: '{p.name}', evr: '{p.evr}', algo: '{p.algo}', expected: '{p.checksum}', found: '{checksum}'"
                )
                raise dnf.exceptions.DepsolveError(msg)

        shutil.copy(p.package.localPkg(), directory)


def hawkey_chksum_to_name(id):
    if id == hawkey.CHKSUM_MD5:  # Devskim: ignore DS126858
        return "md5"  # Devskim: ignore DS126858
    elif id == hawkey.CHKSUM_SHA1:  # Devskim: ignore DS126858
        return "sha1"  # Devskim: ignore DS126858
    elif id == hawkey.CHKSUM_SHA256:
        return "sha256"
    elif id == hawkey.CHKSUM_SHA384:
        return "sha384"
    elif id == hawkey.CHKSUM_SHA512:
        return "sha512"
    raise dnf.exceptions.Error("Unknown checksum value %d" % id)


def raise_no_package_error(pkg):
    msg = f"Package could no longer be found in repositories. Name: '{pkg.name}', evr: '{pkg.evr}'"
    raise dnf.exceptions.DepsolveError(msg)


def get_package(base, pkg):
    """Find packages matching given spec."""
    if pkg.arch:
        pkgs = base.sack.query().filter(name=pkg.name, evr=pkg.evr, arch=pkg.arch).run()
    else:
        pkgs = base.sack.query().filter(name=pkg.name, evr=pkg.evr).run()

    if not pkgs:
        raise_no_package_error(pkg)

    # Filter by checksum manually as hawkey does not support it.
    # A package may be presented with a different checksum algorithm here than when it was originally resolved.
    # Therefore, only bail out here if we find the right type of checksum but no matches, otherwise we'll verify the
    # checksum after downloading the package.
    found_correct_checksum_type = False
    for p in pkgs:
        if p.chksum:
            if p.chksum[1].hex() == pkg.checksum:
                # Found a match, indicate that the checksum is correct and return it.
                pkg.package = p
                pkg.checked = True
                return

            if hawkey_chksum_to_name(p.chksum[0]) == pkg.algo:
                found_correct_checksum_type = True

    if found_correct_checksum_type:
        # Should have found a matching checksum because we found at least one of the same type, but none did.
        raise_no_package_error(pkg)

    # Fallback, just pick the first package and verify the checksum after downloading it.
    pkg.package = pkgs[0]

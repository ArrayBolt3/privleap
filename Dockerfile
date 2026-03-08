## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Note that this file is in the root directory of the privleap source code
## because 'docker build' needs to be able to copy the whole source directory
## into the image, but it appears 'docker build' prevents directory traversal.

FROM debian:13
RUN apt-get update
RUN apt-get install -y debhelper debhelper-compat python3 python3-pam python3-sdnotify autopkgtest mmdebstrap debian-archive-keyring sudo zstd
RUN useradd -m user
RUN adduser user sudo
RUN passwd -d user
COPY . /home/user/privleap
RUN chown -R user:user /home/user/privleap
#LABEL org.opencontainers.image.title="privleap-test-docker"
ENTRYPOINT ["/bin/bash", "-l", "-c"]

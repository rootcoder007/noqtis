# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# noqtis on Wolfi. The build stage compiles noqtis, runs every test, builds
# the consumer program against the install and stages the install in /out;
# the final stage carries the shared library, the header, noqtis.pc and the
# CMake package.
#   docker build -t noqtis .        (or podman build)
#   docker build --target build -t noqtis-build .   (stage with the tests)
# Both images are pinned by digest; the tag is in the comment.

# cgr.dev/chainguard/wolfi-base:latest
FROM cgr.dev/chainguard/wolfi-base@sha256:dbcc3a4a3b1b9e68420a4742940aa6267c97e61811736a5fef0918a06ade1827 AS build
RUN apk add --no-cache build-base cmake pkgconf
WORKDIR /src
COPY . .
RUN cmake -S . -B /b -DCMAKE_BUILD_TYPE=Release -DNQSHARED=ON \
      -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib \
 && cmake --build /b -j"$(nproc)" \
 && ctest --test-dir /b --output-on-failure -j"$(nproc)" \
 && DESTDIR=/out cmake --install /b \
 && tests/consumer/run.sh /out/usr /tmp/use

# cgr.dev/chainguard/wolfi-base:latest
FROM cgr.dev/chainguard/wolfi-base@sha256:dbcc3a4a3b1b9e68420a4742940aa6267c97e61811736a5fef0918a06ade1827
COPY --from=build /out/usr/ /usr/
COPY LICENSE NOTICE /usr/share/licenses/noqtis/
# The noqtis command-line tool joins the image when it exists:
# COPY --from=build /out/usr/bin/noqtis /usr/bin/noqtis
# ENTRYPOINT ["/usr/bin/noqtis"]
LABEL org.opencontainers.image.title="noqtis" \
      org.opencontainers.image.licenses="Apache-2.0 WITH LLVM-exception" \
      org.opencontainers.image.source="https://github.com/rootcoder007/noqtis"

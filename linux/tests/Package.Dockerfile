ARG TEST_BUILD_IMAGE=sb-easy-linux-tested:0.1.0
FROM ${TEST_BUILD_IMAGE}
USER root
COPY linux/tests/package_test.py /tmp/package_test.py
# No service can be activated by maintainer scripts during this build.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends /src/build/linux-desktop/*.deb \
    && rm -rf /var/lib/apt/lists/*
RUN --network=none SBL_PACKAGE_FIXTURE=disposable-build python3 /tmp/package_test.py

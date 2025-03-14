FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel_9_1.23 as builder
ARG IMG=quay.io/redhat-user-workloads/logical-volume-manag-tenant/lvm-operator@sha256:68064cb24efee3d3baa1d87cee91d19c16f68a583f6e7499c86c787cae974d39
ARG LVM_MUST_GATHER=quay.io/redhat-user-workloads/logical-volume-manag-tenant/lvms-must-gather@sha256:8aea8b83615ecf464fccd9364054dfa60e982375d1a3f8bdf53be28378c1a2e0
WORKDIR /operator
COPY ./ ./

RUN mkdir bin && \
    cp /cachi2/output/deps/generic/* bin/ && \
    tar -xvf bin/kustomize.tar.gz -C bin && \
    chmod +x bin/operator-sdk bin/controller-gen

RUN CI_VERSION="4.19.0" IMG=${IMG} LVM_MUST_GATHER=${LVM_MUST_GATHER} ./release/hack/render_templates.sh

FROM scratch

# Copy files to locations specified by labels.
COPY --from=builder /operator/bundle/manifests /manifests/
COPY --from=builder /operator/bundle/metadata /metadata/
COPY --from=builder /operator/bundle/tests/scorecard /tests/scorecard/

# Core bundle labels.
LABEL operators.operatorframework.io.bundle.mediatype.v1=registry+v1
LABEL operators.operatorframework.io.bundle.manifests.v1=manifests/
LABEL operators.operatorframework.io.bundle.metadata.v1=metadata/
LABEL operators.operatorframework.io.bundle.package.v1=lvms-operator

# Operator bundle metadata
LABEL com.redhat.delivery.operator.bundle=true
LABEL com.redhat.openshift.versions="v4.19-v4.20"
LABEL com.redhat.delivery.backport=false

# Standard Red Hat labels
LABEL com.redhat.component="lvms-operator-bundle-container"
LABEL name="lvms4/lvms-operator-bundle"
LABEL version="4.19.0"
LABEL release="1"
LABEL summary="An operator bundle for LVM Storage Operator"
LABEL io.k8s.display-name="lvms-operator-bundle"
LABEL maintainer="Suleyman Akbas <sakbas@redhat.com>"
LABEL description="An operator bundle for LVM Storage Operator"
LABEL io.k8s.description="An operator bundle for LVM Storage Operator"
LABEL url="https://github.com/openshift/lvm-operator"
LABEL vendor="Red Hat, Inc."
LABEL io.openshift.tags="lvms"
LABEL lvms.tags="v4.19"
LABEL distribution-scope="public"

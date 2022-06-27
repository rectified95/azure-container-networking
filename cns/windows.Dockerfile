# Build cns
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.18-windowsservercore-ltsc2022 AS builder
# Build args
ARG VERSION
ARG CNS_AI_PATH
ARG CNS_AI_ID

WORKDIR /usr/local/src/cns

# Copy the source
COPY . .

# Build cns
RUN $Env:CGO_ENABLED=0; go build -v -o /usr/local/bin/azure-cns.exe -ldflags """-X main.version=${env:VERSION} -X ${env:CNS_AI_PATH}=${env:CNS_AI_ID}""" -gcflags="-dwarflocationlists=true" ./cns/service

# Copy into final image
FROM mcr.microsoft.com/windows/servercore:ltsc2022
COPY --from=builder /usr/local/bin/azure-cns.exe \
    /usr/local/bin/azure-cns.exe

ENTRYPOINT ["/usr/local/bin/azure-cns.exe"]
EXPOSE 10090

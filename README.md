# Tracing NGAP protocol

```shell
$ make fiveg
$ sudo ./fiveg <interface name>
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```

# Building

## Install Dependencies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```
## Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/nicolaskribas/ngap-trace.git
```

## Makefile build:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ make fiveg
$ sudo ./fiveg <interface name>
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```

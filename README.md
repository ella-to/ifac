# ifac

Cross-platform TUN interface management with a single multiplexed frame path.
Devices are opened directly through `golang.org/x/sys` on Linux and macOS and
through wireguard-go's Wintun bindings on Windows. Designed for high-traffic
frame routing: lookup and writes take no shared locks (Windows serializes
writes per adapter), and neither `WriteTo` nor `ReadFrom` allocates in steady
state.

## API

```go
// Bring up a TUN interface and start receiving its frames, returning the
// assigned address. With ip == "", the first free IPv4 host address in
// subnet is assigned automatically; otherwise the given ip is used, provided
// it is a usable host address inside subnet and not already in use.
func Up(name string, subnet string, ip string) (string, error)

// Tear the interface down. Its reader goroutine exits and its address is freed.
func Down(name string) error

// Managed interfaces, sorted by name; ips[i] belongs to names[i].
func List() (names []string, ips []string, err error)

// Inject a frame into the interface with address ip (exact match first,
// then deterministic longest-prefix match across managed subnets).
// IPv4-mapped IPv6 destinations (::ffff:a.b.c.d) are treated as IPv4.
func WriteTo(ip string, b []byte) (n int, err error)

// Block until a frame arrives on any managed interface or ctx is canceled;
// copies it into b and reports which interface (by ip) it came from. Returns
// io.ErrShortBuffer if b is smaller than the frame. If an interface's device
// fails, the interface is removed and the failure is returned here with that
// interface's ip.
func ReadFrom(ctx context.Context, b []byte) (ip string, n int, err error)

// Largest supported packet buffer.
const MaxFrameSize = 65535
```

A "frame" is a complete IP packet (TUN operates at layer 3; layer-2 TAP is
not available on modern macOS without third-party kexts, so TUN is used on
all platforms for consistent behavior).

## Example: routing between two interfaces

```go
ipA, _ := ifac.Up("net-a", "10.10.0.0/24", "")          // auto: 10.10.0.1
ipB, _ := ifac.Up("net-b", "10.20.0.0/24", "10.20.0.5") // explicit

buf := make([]byte, ifac.MaxFrameSize)
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
for {
    src, n, err := ifac.ReadFrom(ctx, buf)
    if ctx.Err() != nil {
        return // shutting down
    }
    if err != nil {
        log.Print(err) // a failed interface; buf is MaxFrameSize, so never io.ErrShortBuffer
        continue
    }
    // route: forward frames arriving on A into B and vice versa
    dst := ipB
    if src == ipB {
        dst = ipA
    }
    ifac.WriteTo(dst, buf[:n])
}
```

`ReadFrom` may be called from multiple goroutines to parallelize routing;
each frame is delivered to exactly one caller. Cancel its context during
shutdown so no goroutine remains blocked waiting for traffic.

## Performance notes

- **No locks on the frame path.** Interface lookup in `WriteTo` reads an
  atomically swapped copy-on-write registry keyed by `netip.Addr`. Teardown
  is signalled by a per-interface atomic flag, so writes never contend on a
  shared lock, and writes racing `Down` fail fast with `ErrClosed`.
- **Zero steady-state allocations.** Each device read lands in a
  per-interface scratch buffer and is copied into a pooled buffer sized to
  the packet (2 KB, 16 KB or 64 KB classes), then into the caller's buffer.
  A full queue of MTU-sized frames pins about 2 MB, not 64 MB.
- **Backpressure, not drops.** Per-interface readers block when the shared
  1024-frame queue is full; excess load is shed by the kernel's own device
  queue, exactly as with a physical NIC. Device failures travel on a separate
  queue, so they are reported even when the frame queue is full.
- **Non-blocking fds.** On Linux and macOS devices are registered with the Go
  runtime poller, so per-interface reader goroutines cost no OS threads while
  idle and exit promptly on `Down`.
- **Lifecycle calls run in parallel.** `Up` and `Down` reserve the name,
  address and subnet under a short lock, then run the platform commands
  without it, so one slow command does not block other interfaces.

Run `go test -run '^$' -bench . .` to measure the frame path with an
in-memory device.

## Platform requirements

| | Privileges | Mechanism | Notes |
|---|---|---|---|
| Linux | root (or `CAP_NET_ADMIN`) | `/dev/net/tun` + `ip` (iproute2) | interface named as requested: at most 15 bytes, no `/`, `%`, `:` or whitespace |
| macOS | root | `utun` control socket + `ifconfig`/`route` | kernel only allows `utunN` device names; other names remain the logical handle while the kernel picks the device |
| Windows | Administrator | Wintun + NetTCPIP PowerShell cmdlets | place the architecture-matched `wintun.dll` beside the application; adapters are created and removed dynamically |

Subnets must be IPv4, between `/8` and `/30`, and outside reserved ranges
(`0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`,
`240.0.0.0/4`). Each managed interface needs its own subnet; nested subnets
are allowed and resolved by longest-prefix match. On Linux and macOS the
device itself is removed automatically when `Down` closes its file
descriptor. Windows uses the native layer-3 [Wintun](https://www.wintun.net/)
driver rather than legacy TAP-Windows TUN emulation.

## Testing

Unit tests run anywhere:

```sh
go test ./...
```

The full lifecycle test creates real TUN devices and needs root:

```sh
sudo go test -run TestIntegration -v .
```

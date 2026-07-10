# ifac

Cross-platform TUN interface management with a single multiplexed frame path,
built on the maintained [Doridian/water](https://github.com/Doridian/water)
fork. Designed for
high-traffic frame routing: registry lookup is lock-free and frame delivery
allocates nothing in steady state.

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
func WriteTo(ip string, b []byte) (n int, err error)

// Block until a frame arrives on any managed interface or ctx is canceled;
// copies it into b and reports which interface (by ip) it came from. Returns
// io.ErrShortBuffer if b is smaller than the frame.
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
    if err != nil {
        continue // io.ErrShortBuffer: frame larger than buf was truncated
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

- **Lock-free lookup.** Interface lookup in `WriteTo`/`ReadFrom` reads an
  atomically-swapped copy-on-write registry. Writes use a shared per-interface
  lifecycle guard so `Down` cannot close a device during an in-flight write.
- **Zero steady-state allocations.** Frame buffers come from a `sync.Pool`;
  each frame costs one copy (device → pooled buffer → caller's buffer).
- **Backpressure, not drops.** Per-interface readers block when the shared
  1024-frame queue is full; excess load is shed by the kernel's own device
  queue, exactly as with a physical NIC.
- **Non-blocking fds.** Devices are registered with the Go runtime poller,
  so per-interface reader goroutines cost no OS threads while idle and exit
  promptly on `Down`.

## Platform requirements

| | Privileges | Mechanism | Notes |
|---|---|---|---|
| Linux | root (or `CAP_NET_ADMIN`) | `/dev/net/tun` + `ip` (iproute2) | interface named as requested (≤15 chars) |
| macOS | root | `utun` + `ifconfig`/`route` | kernel only allows `utunN` device names; other names remain the logical handle while the kernel picks the device |
| Windows | Administrator | Wintun + NetTCPIP PowerShell cmdlets | place the architecture-matched `wintun.dll` beside the application; adapters are created and removed dynamically |

Subnets must be IPv4, `/30` or wider. On Linux and macOS the device itself
is removed automatically when `Down` closes its file descriptor. Windows
uses the native layer-3 [Wintun](https://www.wintun.net/) driver rather than
legacy TAP-Windows TUN emulation.

## Testing

Unit tests run anywhere:

```sh
go test ./...
```

The full lifecycle test creates real TUN devices and needs root:

```sh
sudo go test -run TestIntegration -v .
```

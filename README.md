# UDP through Socks5

**Handle protocol udp through proxy socks5 implement for Elixir**

## How to use

```elixir
UDP.Socks5.Sup.start_link(%{})
{:ok, fd} = :gen_udp.open(2021, [:binary, active: true])
args = %{parent: self(), port_open: 2021, proxy: %{proxy: {proxy_ip, proxy_port}, proxy_auth: {user, pass}}}
UDP.Socks5.Sup.start_udp(args)
```

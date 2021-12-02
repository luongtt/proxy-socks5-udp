defmodule UDP.Socks5 do
  @moduledoc """
    handle protocol udp through proxy socks5
  """
  require Logger
  use GenServer

  alias UDP.Socks5.Packet

  def start_link(args) do
    GenServer.start_link(__MODULE__, args, [spawn_opt: [message_queue_data: :off_heap]])
  end

  def init(args) do
    Process.flag(:trap_exit, true)
    Process.put(:debug, true)
    send(self(), :connect)
    parent = Map.get(args, :parent, nil)        #  Parent pid listen packet to handle: {:socks_udp_error, exp}, {:socks_udp, proxy_addr, proxy_port}
    proxy = Map.get(args, :proxy, nil)          #  Proxy format %{proxy: {host_ip, port}, proxy_auth: {user, pass}}
    port_open = Map.get(args, :port_open, 2021) #  UDP port open
    {:ok, %{parent: parent, proxy: proxy, sm: %{fd: nil, port_open: port_open}}}
  end

  def handle_info(:connect, %{parent: parent, sm: sm, proxy: %{proxy: {host_ip, port}}} = state) do
    case :gen_tcp.connect(host_ip, port, [:binary, active: true, packet: 0]) do
      {:ok, fd} ->
        :gen_tcp.send(fd, Packet.auth_method())
        {:noreply, %{state| sm: %{sm| fd: fd}}}
      exp ->
        send(parent, {:socks_udp_error, exp})
        {:stop, :normal, state}
    end
  end

  def handle_info({:tcp, socket, bin}, %{sm: %{fd: socket}} = state) do
    process_socks(Packet.pretty_bin(bin), state)
  end

  def handle_info({:EXIT, pid, reason}, state) do
    if reason != :normal, do: Logger.error("socks_udp error #{inspect pid} message #{inspect reason}")
    {:stop, :normal, state}
  end

  def handle_info(data, state) do
    Logger.error("socks_udp unknown #{inspect data}")
    {:noreply, state}
  end

  def terminate(reason, _data) do
    if reason != :normal do
      Logger.error("stop_socks_udp #{inspect reason}")
    end
    :ok
  end

  def process_socks({:auth_user_pass, _bin}, %{proxy: %{proxy_auth: {user, pass}}, sm: %{fd: socket}} = state) do
    :gen_tcp.send(socket, Packet.auth(user, pass))
    {:noreply, state}
  end

  def process_socks({:auth_success, _bin}, %{sm: %{fd: socket, port_open: port_open}} = state) do
    :gen_tcp.send(socket, Packet.associate(port_open))
    {:noreply, state}
  end

  # Send back to parent proxy info
  def process_socks({:associate_success, <<ip1, ip2, ip3, ip4, proxy_port::16>>},
        %{parent: parent, proxy: %{proxy: {host, _port}}} = state) do
    proxy_addr = '#{ip1}.#{ip2}.#{ip3}.#{ip4}'
    proxy_addr = if proxy_addr === '0.0.0.0', do: host, else: proxy_addr
    send(parent, {:socks_udp, proxy_addr, proxy_port})
    {:noreply, state}
  end

  def process_socks(bin, state) do
    Logger.debug("udp_proxy unknown #{inspect bin}")
    {:noreply, state}
  end
end

defmodule UDP.Socks5.Sup do
  @moduledoc false
  use DynamicSupervisor
  @name :udp_socks5_sup

  def start_link(args) do
    DynamicSupervisor.start_link(__MODULE__, args, name: @name)
  end

  @impl true
  def init(_args) do
    DynamicSupervisor.init(strategy: :one_for_one, extra_arguments: [])
  end

  # parent start_udp(%{parent: self(), port_open: udp_port, proxy: proxy_udp})
  def start_udp(args, link \\ true) do
    spec = %{id: UDP.Socks5, start: {UDP.Socks5, :start_link, [args]}, restart: :temporary, shutdown: 5000}
    ret = DynamicSupervisor.start_child(@name, spec)
    case ret do
      {:ok, pid} ->
        if link == true, do: Process.link(pid)
        ret
      _ ->
        ret
    end
  end
end

defmodule UDP.Socks5.Packet do
  @moduledoc """
    defined packet handshake udp
  """
  @socks_ver 5
  @no_auth 0
  @auth_user_pass 2
  @udp_associate 3
  @addr_ipv4 1
  @sub_negotiation 1
  @reserved 0

  def auth_method() do
    count_method = 2
    <<@socks_ver, count_method, @no_auth, @auth_user_pass>>
  end

  def auth(user, pass) do
    <<@sub_negotiation, byte_size(user)::8, user::binary, byte_size(pass)::8, pass::binary>>
  end

  def associate(port_open) do
    remote_addr = <<0, 0, 0, 0>>
    <<@socks_ver, @udp_associate, @reserved, @addr_ipv4, remote_addr::binary, port_open::16>>
  end

  @success 0
  def pretty_bin(bin) do
    case bin do
      <<@socks_ver, @auth_user_pass>> -> {:auth_user_pass, bin}
      <<@sub_negotiation, @success>> -> {:auth_success, bin}
      <<@socks_ver, @success, @reserved, @addr_ipv4, rest::binary>> -> {:associate_success, rest}
      _ -> {nil, bin}
    end
  end
end

defmodule UDP.Socks5.Util do
  @moduledoc """
    provider func for socks udp
  """
  @addr_ipv4 1
  @reserved 0

  def pack_socks_udp(target_url, target_port, bin) do
    fragment_num = 0
    [_, ip1, ip2, ip3, ip4] = Regex.run(~r/(\d+).(\d+).(\d+).(\d+)/, target_url |> List.to_string())
    <<@reserved::16, fragment_num, @addr_ipv4,
      String.to_integer(ip1), String.to_integer(ip2), String.to_integer(ip3), String.to_integer(ip4), target_port::16,
      bin::binary>>
  end

  def unpack_socks_udp(<<_head::binary-size(10), body::binary>>), do: body
  def unpack_socks_udp(bin), do: bin

  def send_udp(socket, proxy_url, proxy_port, target_url, target_port, bin) do
    :gen_udp.send(socket, proxy_url, proxy_port, pack_socks_udp(target_url, target_port, bin))
  end

  def close(socket) do
    if is_port(socket) do
      :gen_udp.close(socket)
    end
  end
end


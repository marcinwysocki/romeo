defmodule Romeo.Transports.TCP do
  @moduledoc false

  use Gen

  @default_port 5222
  @ssl_opts [reuse_sessions: true]
  @socket_opts [packet: :raw, mode: :binary, active: :once]
  @ns_jabber_client Romeo.XMLNS.ns_jabber_client()
  @ns_component_accept Romeo.XMLNS.ns_component_accept()

  @type state :: Romeo.Connection.t()

  use Romeo.XML

  alias Romeo.Connection.Features
  alias Romeo.Connection, as: Conn

  require Logger

  import Kernel, except: [send: 2]

  @spec connect(Keyword.t()) :: {:ok, state} | {:error, any}
  def connect(%Conn{host: host, port: port, socket_opts: socket_opts, legacy_tls: tls} = conn) do
    host = (host || host(conn.jid)) |> to_charlist()
    port = port || @default_port

    conn = %{conn | host: host, port: port, socket_opts: socket_opts}

    case :gen_tcp.connect(host, port, socket_opts ++ @socket_opts, conn.timeout) do
      {:ok, socket} ->
        Logger.info(fn -> "Established connection to #{host}" end)
        parser = :fxml_stream.new(self(), :infinity, [:no_gen_server])
        conn = %{conn | parser: parser, socket: {:gen_tcp, socket}}
        conn = if tls, do: upgrade_to_tls(conn), else: conn
        start_protocol(conn)

      {:error, _} = error ->
        error
    end
  end

  def disconnect(info, {mod, socket}) do
    :ok = mod.close(socket)

    case info do
      {:close, from} ->
        Connection.reply(from, :ok)

      {:error, :closed} ->
        :error_logger.format("Connection closed~n", [])

      {:error, reason} ->
        reason = :inet.format_error(reason)
        :error_logger.format("Connection error: ~s~n", [reason])
    end
  end

  defp start_protocol(%Conn{component: true} = conn) do
    conn
    |> start_stream(@ns_component_accept)
    |> handshake()
    |> ready()
  end

  defp parse_data(%Conn{jid: jid, parser: parser} = conn, data) do
    Logger.debug(fn -> "[#{jid}][INCOMING] #{inspect(data)}" end)

    parser = :fxml_stream.parse(parser, data)

    stanza =
      case receive_stanza() do
        :more -> :more
        stanza -> stanza
      end

    {:ok, %{conn | parser: parser}, stanza}
  end

  defp receive_stanza(timeout \\ 10) do
    receive do
      {:xmlstreamstart, _, _} = stanza -> stanza
      {:xmlstreamend, _} = stanza -> stanza
      {:xmlstreamraw, stanza} -> stanza
      {:xmlstreamcdata, stanza} -> stanza
      {:xmlstreamerror, _} = stanza -> stanza
      {:xmlstreamelement, stanza} -> stanza
    after
      timeout ->
        :more
    end
  end

  def send(%Conn{jid: jid, socket: {mod, socket}} = conn, stanza) do
    stanza = Romeo.XML.encode!(stanza)
    Logger.debug(fn -> "[#{jid}][OUTGOING] #{inspect(stanza)}" end)
    :ok = mod.send(socket, stanza)
    {:ok, conn}
  end

  # def recv(%Conn{socket: {:ssl, socket}, timeout: timeout} = conn, fun) do
  #   receive do
  #     {:xmlstreamelement, stanza} ->
  #       fun.(conn, stanza)

  #     {:ssl, ^socket, " "} ->
  #       :ok = activate({:ssl, socket})
  #       conn

  #     {:ssl, ^socket, data} ->
  #       :ok = activate({:ssl, socket})

  #       if whitespace_only?(data) do
  #         conn
  #       else
  #         {:ok, conn, stanza} = parse_data(conn, data)
  #         fun.(conn, stanza)
  #       end

  #     {:ssl_closed, ^socket} ->
  #       {:error, :closed}

  #     {:ssl_error, ^socket, reason} ->
  #       {:error, reason}
  #   after
  #     timeout ->
  #       Kernel.send(self(), {:error, :timeout})
  #       conn
  #   end
  # end

  def handle_message({:tcp, socket, data}, %{socket: {:gen_tcp, socket}} = conn) do
    :ok = activate({:gen_tcp, socket})

    if whitespace_only?(data) do
      {:ok, conn, :noreply}
    else
      parse_data(conn, data) |> handle_stanza()
    end
  end

  def handle_message({:xmlstreamelement, stanza}, conn) do
    handle_stanza({:ok, conn, stanza})
  end

  def handle_message({:tcp_closed, socket}, %{socket: {:gen_tcp, socket}}) do
    {:error, :closed}
  end

  def handle_message({:tcp_error, socket, reason}, %{socket: {:gen_tcp, socket}}) do
    {:error, reason}
  end

  def handle_message({:ssl, socket, data}, %{socket: {:ssl, socket}} = conn) do
    {:ok, _, _} = handle_data(data, conn)
  end

  def handle_message({:ssl_closed, socket}, %{socket: {:ssl, socket}}) do
    {:error, :closed}
  end

  def handle_message({:ssl_error, socket, reason}, %{socket: {:ssl, socket}}) do
    {:error, reason}
  end

  def handle_message(_, _), do: :unknown

  defp start_protocol(%Conn{} = conn) do
    start_stream(conn, @ns_jabber_client)

    # maybe_start_tls()
    # |> authenticate()
    |> bind()
    |> session()
    |> ready()
  end

  defp start_stream(%Conn{jid: jid} = conn, xmlns \\ @ns_jabber_client) do
    send(conn, jid |> host |> Romeo.Stanza.start_stream(xmlns))

    conn
  end

  defp negotiate_features(%Conn{} = conn) do
    recv(conn, fn conn, xmlel(name: "stream:features") = packet ->
      %{conn | features: Features.parse_stream_features(packet)}
    end)
  end

  # defp maybe_start_tls(%Conn{features: %Features{tls?: true}} = conn) do
  #   send(conn, Stanza.start_tls())
  # end

  # defp maybe_start_tls(%Conn{} = conn), do: conn

  # defp upgrade_to_tls(%Conn{parser: parser, socket: {:gen_tcp, socket}} = conn) do
  #   Logger.info(fn -> "Negotiating secure connection" end)

  #   {:ok, socket} = :ssl.connect(socket, conn.ssl_opts ++ @ssl_opts)
  #   parser = :fxml_stream.reset(parser)

  #   Logger.info(fn -> "Connection successfully secured" end)
  #   %{conn | socket: {:ssl, socket}, parser: parser}
  # end

  defp authenticate(%Conn{} = conn) do
    conn
    |> Romeo.Auth.authenticate!()
    |> reset_parser
    |> start_stream
  end

  defp handshake(%Conn{} = conn) do
    Romeo.Auth.handshake!(conn)
  end

  defp session(%Conn{} = conn) do
    stanza = Romeo.Stanza.session()
    id = Romeo.XML.attr(stanza, "id")

    conn
    |> send(stanza)

    conn
  end

  defp ready(%Conn{owner: owner} = conn) do
    Kernel.send(owner, :connection_ready)
    {:ok, conn}
  end

  defp reset_parser(%Conn{parser: parser} = conn) do
    parser = :fxml_stream.reset(parser)
    %{conn | parser: parser}
  end

  defp handle_data(data, %{socket: socket} = conn) do
    :ok = activate(socket)

    conn |> parse_data(data) |> handle_stanza(conn)
  end

  # session start
  defp handle_stanza({:ok, conn, :more} = resp), do: resp

  defp handle_stanza({:ok, conn, xmlstreamstart(attrs: attrs) = stanza}) do
    {"id", id} = List.keyfind(attrs, "id", 0)

    {:ok, %{conn | stream_id: id}, :noreply}
  end

  defp handle_stanza({:ok, conn, xmlel(name: "stream:features") = stanza}) do
    new_conn =
      conn
      |> Map.put(:features, Features.parse_stream_features(stanza))
      |> authenticate()
      |> bind()

    {:ok, new_conn, :noreply}
  end

  defp handle_stanza(
         {:ok, %Conn{bind_iq_id: bind_iq_id, session_iq_id: session_iq_id},
          xmlel(name: "iq") = stanza}
       )
       when not is_nil(bind_iq_id) do
    case Romeo.XML.attr(stanza, "type") do
      "result" ->
        case Romeo.XML.attr(stanza, "id") do
          ^bind_iq_id ->
            %Romeo.JID{resource: resource} =
              stanza
              |> Romeo.XML.subelement("bind")
              |> Romeo.XML.subelement("jid")
              |> Romeo.XML.cdata()
              |> Romeo.JID.parse()

            Logger.info(fn -> "Bound to resource: #{resource}" end)
            Kernel.send(owner, {:resource_bound, resource})

            new_conn = %{conn | resource: resource}

            session(new_conn)

            {:ok, new_conn, :noreply}

          ^session_iq_id ->
            Logger.info(fn -> "Session established" end)
            conn

          _ ->
            {:ok, conn, stanza}
        end

      _ ->
        {:ok, conn, stanza}
    end
  end

  defp bind(%Conn{resource: resource, bind_iq_id: nil} = conn) do
    stanza = Romeo.Stanza.bind(resource)
    id = Romeo.XML.attr(stanza, "id")

    {:ok, _} = send(conn, stanza)

    Map.put(conn, :bind_iq_id, id)
  end

  defp bind(conn), do: conn

  # defp handle_stanza({:ok, conn, xmlel(name: "proceed") = stanza}) do
  #   new_conn = conn |> upgrade_to_tls() |> start_stream()

  #   {:ok, new_conn, :noreply}
  # end

  defp whitespace_only?(data), do: Regex.match?(~r/^\s+$/, data)

  defp activate({:gen_tcp, socket}) do
    case :inet.setopts(socket, active: :once) do
      :ok ->
        :ok

      {:error, :closed} ->
        _ = Kernel.send(self(), {:tcp_closed, socket})
        :ok

      {:error, reason} ->
        _ = Kernel.send(self(), {:tcp_error, socket, reason})
        :ok
    end
  end

  defp activate({:ssl, socket}) do
    case :ssl.setopts(socket, active: :once) do
      :ok ->
        :ok

      {:error, :closed} ->
        _ = Kernel.send(self(), {:ssl_closed, socket})
        :ok

      {:error, reason} ->
        _ = Kernel.send(self(), {:ssl_error, socket, reason})
        :ok
    end
  end

  defp host(jid) do
    Romeo.JID.parse(jid).server
  end
end

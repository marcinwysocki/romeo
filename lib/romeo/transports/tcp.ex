defmodule Romeo.Transports.TCP do
  @moduledoc false

  use GenServer

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

  def connect(%Conn{socket_server: server}) do
    GenServer.call(server, :connect)
  end

  ### GenServer

  def start_link(conn) do
    GenServer.start_link(__MODULE__, conn)
  end

  def init(conn) do
    {:ok, conn}
  end

  def handle_call(
        :connect,
        from,
        conn
      ) do
    case do_connect(%{conn | initiator: from}) do
      {:ok, new_conn} ->
        {:noreply, new_conn}

      err ->
        {:stop, err, conn}
    end
  end

  @spec do_connect(Keyword.t()) :: {:ok, state} | {:error, any}
  def do_connect(%Conn{host: host, port: port, socket_opts: socket_opts} = conn) do
    host = (host || host(conn.jid)) |> to_charlist()
    port = port || @default_port

    conn = %{conn | host: host, port: port, socket_opts: socket_opts}

    case :gen_tcp.connect(host, port, socket_opts ++ @socket_opts, conn.timeout) do
      {:ok, socket} ->
        Logger.info(fn -> "Established connection to #{host}" end)
        parser = :fxml_stream.new(self(), :infinity, [:no_gen_server])
        conn = %{conn | parser: parser, socket: {:gen_tcp, socket}}
        # conn = if tls, do: upgrade_to_tls(conn), else: conn
        case start_protocol(conn) do
          %Conn{} = conn -> {:ok, conn}
          err -> err
        end

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

  def send(%Conn{jid: jid, socket: {mod, socket}} = conn, stanza) do
    stanza = Romeo.XML.encode!(stanza)
    Logger.debug(fn -> "[#{jid}][OUTGOING] #{inspect(stanza)}" end)
    :ok = mod.send(socket, stanza)
    {:ok, conn}
  end

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

  def handle_message(_, _), do: :unknown

  ### PRIVATE ###

  # TODO: implement handshake if necessary
  #
  # defp start_protocol(%Conn{component: true} = conn) do
  #   conn
  #   |> start_stream(@ns_component_accept)
  #   |> handshake()
  #   |> ready()
  # end

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

  ### SESSION INITIALIZATION ###

  defp start_protocol(%Conn{} = conn) do
    start_stream(conn, @ns_jabber_client)
  end

  defp start_stream(%Conn{jid: jid} = conn, xmlns \\ @ns_jabber_client) do
    send(conn, jid |> host |> Romeo.Stanza.start_stream(xmlns))

    conn
  end

  defp authenticate(%Conn{} = conn) do
    Romeo.Auth.authenticate!(conn)
  end

  # TODO: uses Tcp.receive/2 under the hood. Has to be reimplemented
  #
  # defp handshake(%Conn{} = conn) do
  #   Romeo.Auth.handshake!(conn)
  # end

  defp bind(%Conn{resource: resource, bind_iq_id: nil} = conn) do
    stanza = Romeo.Stanza.bind(resource)
    id = Romeo.XML.attr(stanza, "id")

    {:ok, _} = send(conn, stanza)

    Map.put(conn, :bind_iq_id, id)
  end

  defp bind(conn), do: conn

  defp session(%Conn{} = conn) do
    stanza = Romeo.Stanza.session()
    id = Romeo.XML.attr(stanza, "id")

    conn
    |> send(stanza)

    Map.put(conn, :session_iq_id, id)
  end

  defp ready(%Conn{owner: owner} = conn) do
    Kernel.send(owner, :connection_ready)
    {:ok, conn}
  end

  defp reset_parser(%Conn{parser: parser} = conn) do
    parser = :fxml_stream.reset(parser)
    %{conn | parser: parser}
  end

  ### STANZAS ###

  # session initialization
  defp handle_stanza({:ok, conn, xmlstreamstart(attrs: attrs)}) do
    {"id", id} = List.keyfind(attrs, "id", 0)

    {:ok, %{conn | stream_id: id}, :noreply}
  end

  defp handle_stanza({:ok, conn, xmlel(name: "stream:features") = stanza}) do
    new_conn =
      conn
      |> Map.put(:features, Features.parse_stream_features(stanza))
      |> authenticate()

    {:ok, new_conn, :noreply}
  end

  defp handle_stanza({:ok, conn, xmlel(name: "success")}) do
    Logger.info(fn -> "Authenticated successfully" end)

    new_conn =
      conn
      |> reset_parser()
      |> start_stream()
      |> bind()

    {:ok, new_conn, :noreply}
  end

  defp handle_stanza({:ok, _, xmlel(name: "failure")}) do
    raise Romeo.Auth.Error, ""
  end

  defp handle_stanza(
         {:ok,
          %Conn{
            owner: owner,
            bind_iq_id: bind_iq_id,
            session_iq_id: session_iq_id,
            initiator: initiator
          } = conn, xmlel(name: "iq") = stanza}
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

            {:ok, new_conn} = ready(conn)

            GenServer.reply(initiator, {:ok, new_conn})

            {:ok, new_conn, :noreply}

          _ ->
            {:ok, conn, stanza}
        end

      _ ->
        {:ok, conn, stanza}
    end
  end

  # regular stanzas
  defp handle_stanza({:ok, _, :more} = resp), do: resp
  defp handle_stanza({:ok, _, _} = resp), do: resp

  #### HELPERS ####

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

  defp host(jid) do
    Romeo.JID.parse(jid).server
  end

  # TODO: TLS related features are not supported in this version. Below is the old implementation.
  #
  # defp activate({:ssl, socket}) do
  #   case :ssl.setopts(socket, active: :once) do
  #     :ok ->
  #       :ok

  #     {:error, :closed} ->
  #       _ = Kernel.send(self(), {:ssl_closed, socket})
  #       :ok

  #     {:error, reason} ->
  #       _ = Kernel.send(self(), {:ssl_error, socket, reason})
  #       :ok
  #   end
  # end
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

  # def handle_message({:ssl, socket, data}, %{socket: {:ssl, socket}} = conn) do
  #   {:ok, _, _} = handle_data(data, conn)
  # end

  # def handle_message({:ssl_closed, socket}, %{socket: {:ssl, socket}}) do
  #   {:error, :closed}
  # end

  # def handle_message({:ssl_error, socket, reason}, %{socket: {:ssl, socket}}) do
  #   {:error, reason}
  # end
end

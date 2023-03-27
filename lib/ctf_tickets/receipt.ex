defmodule CtfTickets.Receipt do
  alias CtfTickets.Ticket
  alias CtfTickets.Sockaddr

  defstruct secret_key: nil,
            slug: nil,
            connected_ip: nil,
            connected_at: nil,
            serialized: nil

  @type t :: %__MODULE__{
          secret_key: binary(),
          slug: String.t(),
          connected_ip: :inet.ip_address(),
          connected_at: NaiveDateTime.t(),
          serialized: String.t() | nil
        }

  @matcher ~r/^
    (?'preamble'flag\{)?
    (?'slug'[0-9a-zA-Z]+)
    :
    (?'nonce'[a-zA-Z0-9_\-]{16})
    (?'blob'[a-zA-Z0-9_\-]+) # { fix regex
    (?'coda'})?
    $/ix

  # ' # fix regex

  @spec initialize(
          secret_key :: binary(),
          ticket :: Ticket.t(),
          ip_address :: :inet.ip_address()
        ) :: __MODULE__.t()
  @spec initialize(
          secret_key :: binary(),
          ticket :: Ticket.t(),
          ip_address :: :inet.ip_address(),
          connected_at :: NaiveDateTime.t()
        ) :: __MODULE__.t()
  def initialize(secret_key, ticket, ip_address, connected_at \\ NaiveDateTime.utc_now()) do
    %__MODULE__{
      secret_key: secret_key,
      slug: ticket.slug,
      connected_ip: ip_address,
      connected_at: connected_at
    }
  end

  @doc ~S"""
  Deserializes a serialized receipt into a CtfTickets.Receipt

  ## Example

  iex> serialized = "flag{22weatherdeckweatherdeckweatherdeck123456:YWFhYWFhYWFhYWFh1V3Eo1SvtdoAD4ClceRltjyV6R61QjFTh8HwWYbNbEyISjP38alDIwXTDb1skp0fC3zJWQ}"
  iex> secret_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  iex> {:ok, expected_addr} = :inet.parse_address('fe80::7483:c2ff:0069:0420')
  iex> expected_time = 1679863080 |> DateTime.from_unix!() |> DateTime.to_naive()
  iex> CtfTickets.Receipt.deserialize(secret_key, serialized)
  %CtfTickets.Receipt{slug: "22weatherdeckweatherdeckweatherdeck123456",
  connected_ip: expected_addr,
  connected_at: expected_time,
  serialized: serialized,
  secret_key: secret_key}
  """
  @spec deserialize(secret_key :: binary(), serialized :: binary()) :: __MODULE__.t()
  def deserialize(secret_key, serialized) do
    unmatch_result =
      @matcher
      |> Regex.named_captures(serialized)
      |> unmatch(secret_key)

    case unmatch_result do
      {:error, reason} ->
        {:error, reason}

      receipt = %__MODULE__{} ->
        struct(receipt, %{serialized: serialized, secret_key: secret_key})
    end
  end

  @spec serialize(receipt :: __MODULE__.t()) :: String.t()
  def serialize(%__MODULE__{serialized: serialized}) when is_binary(serialized) do
    serialized
  end

  def serialize(%__MODULE__{
        secret_key: secret_key,
        slug: slug,
        connected_ip: connected_ip,
        connected_at: connected_at
      }) do
    sockaddr = Sockaddr.encode(connected_ip)

    time_i =
      connected_at
      |> DateTime.from_naive!("Etc/UTC")
      |> DateTime.to_unix()

    blob = <<time_i::big-integer-unsigned-size(64), sockaddr::bytes>>
    nonce = CtfTickets.mk_nonce()
    payload = CtfTickets.encrypt(blob, slug, nonce, secret_key)

    [
      "flag{",
      slug,
      ":",
      Base.url_encode64(nonce, padding: false),
      Base.url_encode64(payload, padding: false),
      "}"
    ]
    |> Enum.join()
  end

  defp unmatch(nil, _secret_Key), do: {:error, "couldn't parse"}

  defp unmatch(
         %{"slug" => slug, "nonce" => nonce_u64, "blob" => blob_u64},
         secret_key
       ) do
    with {:ok, nonce} = Base.url_decode64(nonce_u64, padding: false),
         {:ok, blob} = Base.url_decode64(blob_u64, padding: false),
         packed_payload = CtfTickets.decrypt(blob, slug, nonce, secret_key),

         # Packs the connected_at and sockaddr (16-byte string)
         # PACKER = 'Q>a28'
         <<time_i::big-integer-unsigned-size(64), sockaddr::bytes>> = packed_payload,
         {:ok, time_tz} = DateTime.from_unix(time_i),
         time = DateTime.to_naive(time_tz),
         addr = Sockaddr.decode(sockaddr) do
      %__MODULE__{
        slug: slug,
        connected_ip: addr,
        connected_at: time
      }
    end
  end
end

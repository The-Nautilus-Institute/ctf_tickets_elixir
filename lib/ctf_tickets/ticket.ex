defmodule CtfTickets.Ticket do
  defstruct secret_key: nil,
            slug: nil,
            seed: nil,
            serialized: nil

  @type t :: %__MODULE__{
          slug: String.t(),
          seed: non_neg_integer(),
          secret_key: binary(),
          serialized: String.t() | nil
        }

  @matcher ~r/^
            (?'preamble'ticket\{)?
            (?'slug'[0-9a-zA-Z]+)
            :
            (?'nonce'[a-zA-Z0-9_\-]{16})
            (?'blob'[a-zA-Z0-9_\-]+) # { fix regex
            (?'coda'})?
            $/ix

  # ' # fix regex

  @spec initialize(secret_key :: binary(), slug :: String.t()) :: __MODULE__.t()
  def initialize(secret_key, slug) do
    initialize(secret_key, slug, CtfTickets.mk_seed())
  end

  @spec initialize(
          secret_key :: binary(),
          slug :: String.t(),
          seed :: non_neg_integer()
        ) :: __MODULE__.t()
  def initialize(secret_key, slug, seed) do
    %__MODULE__{slug: slug, secret_key: secret_key, seed: seed}
  end

  @doc ~S"""
  Deserializes a serialzed ticket into a CtfTickets.Ticket

  ## Example

  iex> serialized = "ticket{22weatherdeckweatherdeckweatherdeck123456:YWFhYWFhYWFhYWFh1V3EozCPGPJABQN6B3BqWEUM7wYr0uOr}"
  iex> secret_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  iex> CtfTickets.Ticket.deserialize(secret_key, serialized)
  %CtfTickets.Ticket{slug: "22weatherdeckweatherdeckweatherdeck123456", seed: 0, serialized: serialized, secret_key: secret_key}
  """
  @spec deserialize(secret_key :: binary(), serialized :: String.t()) ::
          __MODULE__.t() | {:error, reason :: String.t()}
  def deserialize(secret_key, serialized) do
    unmatch_result =
      @matcher
      |> Regex.named_captures(serialized)
      |> unmatch(secret_key)

    case unmatch_result do
      {:error, reason} -> {:error, reason}
      ticket = %__MODULE__{} -> struct(ticket, %{serialized: serialized, secret_key: secret_key})
    end
  end

  defp unmatch(nil, _secret_key), do: {:error, "couldn't parse"}

  defp unmatch(
         %{"slug" => slug, "nonce" => nonce_u64, "blob" => blob_u64},
         secret_key
       ) do
    with {:ok, nonce} <- Base.url_decode64(nonce_u64),
         {:ok, blob} <- Base.url_decode64(blob_u64),
         <<seed::big-integer-signed-size(64)>> <-
           CtfTickets.decrypt(blob, slug, nonce, secret_key) do
      # seed  'Q>' 64-bit uint big-endian

      %__MODULE__{slug: slug, seed: seed}
    end
  end

  @doc ~S"""
  Serializes a Ticket into a string
  """
  @spec serialize(ticket :: __MODULE__.t()) :: String.t()
  def serialize(%__MODULE__{serialized: serialized}) when is_binary(serialized) do
    serialized
  end

  def serialize(%__MODULE__{slug: slug, seed: seed, secret_key: secret_key}) do
    seed_bin = <<seed::big-integer-unsigned-size(64)>>
    nonce = CtfTickets.mk_nonce()
    blob = CtfTickets.encrypt(seed_bin, slug, nonce, secret_key)

    [
      "ticket{",
      slug,
      ":",
      Base.url_encode64(nonce, padding: false),
      Base.url_encode64(blob, padding: false),
      "}"
    ]
    |> Enum.join()
  end
end

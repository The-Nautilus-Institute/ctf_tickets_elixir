defmodule CtfTickets.Ticket do
  defstruct slug: nil,
            seed: nil,
            secret_key: nil,
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

  @spec initialize(slug :: String.t(), secret_key :: binary()) :: __MODULE__.t()
  def initialize(slug, secret_key) do
    initialize(slug, secret_key, CtfTickets.mk_seed())
  end

  @spec initialize(
          slug :: String.t(),
          secret_key :: binary(),
          seed :: non_neg_integer()
        ) :: __MODULE__.t()
  def initialize(slug, secret_key, seed) do
    %__MODULE__{slug: slug, secret_key: secret_key, seed: seed}
  end

  @spec deserialize(serialized :: String.t(), secret_key :: binary()) ::
          __MODULE__.t() | {:error, reason :: string()}
  def deserialize(serialized, secret_key) do
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
    with {:ok, nonce} = Base.url_decode64(nonce_u64),
         {:ok, blob} = Base.url_decode64(blob_u64),
         {:ok, seed_bin} = CtfTickets.cipher().decrypt(blob, slug, nonce, secret_key) do
      # seed  'Q>' 64-bit uint big-endian
      <<seed::big-integer-unsigned-size(64)>> = seed_bin
      %__MODULE__{slug: slug, seed: seed}
    end
  end

  @spec serialize(ticket :: __MODULE__.t()) :: String.t()
  def serialize(%__MODULE__{serialized: serialized}) when is_binary(serialized) do
    serialized
  end

  def serialize(%__MODULE__{slug: slug, seed: seed, secret_key: secret_key}) do
    seed_bin = <<seed::big-integer-unsigned-size(64)>>
    nonce = CtfTickets.mk_nonce()
    blob = CtfTickets.cipher().encrypt(seed_bin, slug, nonce, secret_key)

    ["ticket{",
     slug,
     ":",
     Base.url_encode64(nonce),
     Base.url_encode64(blob),
     "}"]
    |> Enum.join()
  end
end

defmodule CtfTickets do
  @moduledoc """
  Documentation for `CtfTickets`.
  """

  @cipher :libsodium_crypto_aead_chacha20poly1305
  @nonce_len @cipher.npubbytes()
  @max_seed 2 ** 64 - 1

  @spec cipher :: atom()
  def cipher, do: @cipher

  @spec nonce_len :: non_neg_integer()
  def nonce_len, do: @nonce_len

  @spec max_seed :: pos_integer()
  def max_seed, do: @max_seed

  @spec mk_seed :: non_neg_integer()
  def mk_seed, do: :crypto.rand_uniform(0, max_seed + 1)

  @spec mk_nonce :: binary()
  def mk_nonce, do: :crypto.strong_rand_bytes(nonce_len())
end

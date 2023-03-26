defmodule CtfTickets do
  @moduledoc """
  Documentation for `CtfTickets`.
  """

  @cipher :libsodium_crypto_aead_chacha20poly1305
  @nonce_len @cipher.ietf_npubbytes()
  @key_len @cipher.ietf_keybytes()
  @max_seed 2 ** 64 - 1

  @spec encrypt(
          plaintext :: binary(),
          additional :: binary(),
          nonce :: binary(),
          secret_key :: binary()
        ) :: binary()
  def encrypt(plaintext, additional, nonce, secret_key) do
    @cipher.ietf_encrypt(plaintext, additional, nonce, secret_key)
  end

  @spec decrypt(
          ciphertext :: binary(),
          additional :: binary(),
          nonce :: binary(),
          secret_key :: binary()
        ) :: binary()
  def decrypt(ciphertext, additional, nonce, secret_key) do
    @cipher.ietf_decrypt(ciphertext, additional, nonce, secret_key)
  end

  @spec nonce_len :: non_neg_integer()
  def nonce_len, do: @nonce_len

  @spec key_len :: non_neg_integer()
  def key_len, do: @key_len

  @spec max_seed :: pos_integer()
  def max_seed, do: @max_seed

  @spec mk_seed :: non_neg_integer()
  def mk_seed, do: :rand.uniform(max_seed() + 1)

  @spec mk_nonce :: binary()
  def mk_nonce, do: :crypto.strong_rand_bytes(nonce_len())

  @spec mk_key :: binary()
  def mk_key, do: :crypto.strong_rand_bytes(key_len())
end

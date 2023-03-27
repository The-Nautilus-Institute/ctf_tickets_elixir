defmodule ReceiptTest do
  use ExUnit.Case
  doctest CtfTickets.Receipt

  test "serializes and deserializes", ctx do
    receipt =
      CtfTickets.Receipt.initialize(
        ctx[:secret_key],
        ctx[:ticket],
        ctx[:ip_address]
      )

    serialized = CtfTickets.Receipt.serialize(receipt)

    assert String.valid?(serialized)

    d_receipt = CtfTickets.Receipt.deserialize(ctx[:secret_key], serialized)

    assert ctx[:slug] == d_receipt.slug
    assert ctx[:ip_address] == d_receipt.connected_ip

    assert receipt.connected_at |> NaiveDateTime.truncate(:second) ==
             d_receipt.connected_at
  end

  test "serializes and deserializes with ip6 in play", ctx do
    receipt =
      CtfTickets.Receipt.initialize(
        ctx[:secret_key],
        ctx[:ticket],
        ctx[:ip6_address]
      )

    serialized = CtfTickets.Receipt.serialize(receipt)

    assert String.valid?(serialized)

    d_receipt = CtfTickets.Receipt.deserialize(ctx[:secret_key], serialized)

    assert ctx[:slug] == d_receipt.slug
    assert ctx[:ip6_address] == d_receipt.connected_ip

    assert receipt.connected_at |> NaiveDateTime.truncate(:second) ==
             d_receipt.connected_at
  end

  setup do
    key = CtfTickets.mk_key()
    slug = mk_slug()
    seed = CtfTickets.mk_seed()

    ticket = CtfTickets.Ticket.initialize(key, slug, seed)

    [
      secret_key: key,
      slug: slug,
      ticket: ticket,
      ip_address: {127, 0, 0, 1},
      ip6_address: {0xFE80, 0, 0, 0, 0x7483, 0xC2FF, 0x0069, 0x0420}
    ]
  end

  def mk_slug do
    [
      "22",
      "weatherdeck",
      "weatherdeck",
      "weatherdeck",
      :rand.uniform(999_999) |> to_string()
    ]
    |> Enum.join()
  end
end

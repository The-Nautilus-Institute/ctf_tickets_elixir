defmodule TicketTest do
  use ExUnit.Case
  doctest CtfTickets.Ticket

  test "serializes and deserializes", ctx do
    %CtfTickets.Ticket{} =
      ticket =
      CtfTickets.Ticket.initialize(
        ctx[:secret_key],
        ctx[:slug],
        ctx[:seed]
      )

    serialized = CtfTickets.Ticket.serialize(ticket)

    assert String.valid?(serialized)

    d_ticket = CtfTickets.Ticket.deserialize(ctx[:secret_key], serialized)

    assert ctx[:slug] == d_ticket.slug
    assert ctx[:seed] == d_ticket.seed
  end

  setup _context do
    [secret_key: CtfTickets.mk_key(), seed: CtfTickets.mk_seed(), slug: mk_slug()]
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

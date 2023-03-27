defmodule CtfTickets.Sockaddr do
  @spec encode(ip_address :: :inet.ip_address()) :: binary()
  def encode({a, b, c, d}) do
    <<0x10, 2, 0::big-integer-size(16), a, b, c, d, 0::integer-unit(8)-size(8)>>
  end

  def encode({a, b, c, d, e, f, g, h}) do
    <<0x1C, 30, 0::big-integer-size(16), 0::big-integer-size(32), a::big-integer-size(16),
      b::big-integer-size(16), c::big-integer-size(16), d::big-integer-size(16),
      e::big-integer-size(16), f::big-integer-size(16), g::big-integer-size(16),
      h::big-integer-size(16), 0::big-integer-size(32)>>
  end

  @spec decode(sockaddr :: binary()) :: :inet.ip_address()
  # af_inet: 16 = len, 2 = address family, 2 * port, {a, b, c, d}, 8 * padding
  # len
  def decode(<<
        0x10,
        # AF_INET family
        2,
        _port::big-integer-size(16),
        # octets
        a,
        b,
        c,
        d,
        _padding::binary-size(8)
      >>) do
    {a, b, c, d}
  end

  # af_inet6: 0x1c = len, 30 = address family, 2 * port, flowinfo, addr, scope
  # len
  def decode(<<
        0x1C,
        # AF_INET6 family
        30,
        _port::big-integer-size(16),
        _flowinfo::big-integer-size(32),
        a::big-integer-size(16),
        b::big-integer-size(16),
        c::big-integer-size(16),
        d::big-integer-size(16),
        e::big-integer-size(16),
        f::big-integer-size(16),
        g::big-integer-size(16),
        h::big-integer-size(16),
        _scope::big-integer-size(32)
      >>) do
    # AF_INET6
    {a, b, c, d, e, f, g, h}
  end
end

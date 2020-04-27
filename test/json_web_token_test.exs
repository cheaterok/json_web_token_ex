defmodule JsonWebTokenVivoxTest do
  use ExUnit.Case

  doctest JsonWebTokenVivox

  @hs256_key "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
  @claims %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}

  defp sign_does_verify(options, claims \\ @claims) do
    jwt = JsonWebTokenVivox.sign(claims, options)
    {:ok, verified_claims} = JsonWebTokenVivox.verify(jwt, options)
    assert verified_claims === claims
  end

  test "sign/2 jwt w default alg does verify/2" do
    sign_does_verify(%{key: @hs256_key})
  end

  test "sign/2 w HS256 alg does verify/2" do
    sign_does_verify(%{alg: "HS256", key: @hs256_key})
  end

  test "sign/2 w 'none' alg (and no key) does verify/2" do
    sign_does_verify(%{alg: "none"})
  end
end

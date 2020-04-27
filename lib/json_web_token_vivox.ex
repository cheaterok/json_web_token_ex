defmodule JsonWebTokenVivox do
  @moduledoc """
  Top level interface, or API, for signing and verifying a JSON Web Token (JWT)

  see http://tools.ietf.org/html/rfc7519
  """

  alias JsonWebTokenVivox.Jwt

  @doc """
  Return a JSON Web Token (JWT), a string representing a set of claims as a JSON object that is
  encoded in a JWS

  ## Example
      iex> claims = %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}
      ...> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebTokenVivox.sign(claims, %{key: key})
      "e30.eyJpc3MiOiJqb2UiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiZXhwIjoxMzAwODE5MzgwfQ.plU1Xpbfj9aoI6L-UH8vN-tmunhzV_yCMT3Y80yviUw"

  see http://tools.ietf.org/html/rfc7519#section-7.1
  """
  def sign(claims, options), do: Jwt.sign(claims, options)

  @doc """
  Return a tuple {:ok, claims (map)} if the JWT signature is verified,
  or {:error, "invalid"} otherwise

  ## Example
      iex> jwt = "e30.eyJpc3MiOiJqb2UiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiZXhwIjoxMzAwODE5MzgwfQ.plU1Xpbfj9aoI6L-UH8vN-tmunhzV_yCMT3Y80yviUw"
      ...> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebTokenVivox.verify(jwt, %{key: key})
      {:ok, %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}}

  see http://tools.ietf.org/html/rfc7519#section-7.2
  """
  def verify(jwt, options), do: Jwt.verify(jwt, options)
end

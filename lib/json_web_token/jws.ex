defmodule JsonWebTokenVivox.Jws do
  @moduledoc """
  Represent content to be secured with digital signatures or Message Authentication Codes (MACs)

  see http://tools.ietf.org/html/rfc7515
  """

  alias JsonWebTokenVivox.Jwa
  alias JsonWebTokenVivox.Util

  @signed_message_parts 3

  @doc """
  Return a JSON Web Signature (JWS), a string representing a digitally signed payload

  ## Example
      iex> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebTokenVivox.Jws.sign(%{alg: "HS256"}, "payload", key)
      "eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4"
  """
  def sign(header, payload, key) do
    {alg, header} = algorithm(header)
    signing_input = signing_input(header, payload)
    "#{signing_input}.#{signature(alg, key, signing_input)}"
  end

  @doc """
  Return a JWS that provides no integrity protection (i.e. lacks a signature)

  ## Example
      iex> JsonWebTokenVivox.Jws.unsecured_message(%{alg: "none"}, "payload")
      "eyJhbGciOiJub25lIn0.cGF5bG9hZA."

  see http://tools.ietf.org/html/rfc7515#page-47
  """
  def unsecured_message(header, payload) do
    check_alg_value_none(algorithm header)
    "#{signing_input(header, payload)}." # note the trailing "."
  end

  defp algorithm(header) do
    {Util.validate_present(header[:alg]), Map.delete(header, :alg)}
  end

  defp signing_input(header, payload) do
    "#{to_json_base64_encode(header)}.#{Base.url_encode64(payload, padding: false)}"
  end

  defp to_json_base64_encode(header) do
    header
    |> Poison.encode
    |> header_json
    |> Base.url_encode64(padding: false)
  end

  defp header_json({:ok, json}), do: json
  defp header_json({:error, _}), do: raise "Failed to encode header as JSON"

  defp signature(algorithm, key, signing_input) do
    Jwa.sign(algorithm, key, signing_input)
    |> Base.url_encode64(padding: false)
  end

  defp check_alg_value_none("none"), do: true
  defp check_alg_value_none(_), do: raise "Invalid 'alg' header parameter"

  @doc """
  Return a tuple {:ok, jws (string)} if the signature is verified, or {:error, "invalid"} otherwise

  ## Example
      iex> jws = "eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4"
      ...> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebTokenVivox.Jws.verify(jws, "HS256", key)
      {:ok, "eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.uVTaOdyzp_f4mT_hfzU8LnCzdmlVC4t2itHDEYUZym4"}
  """
  def verify(jws, algorithm, key \\ nil) do
    validate_empty_header(jws)
    verified(jws, algorithm, key)
  end

  defp validate_empty_header(jws) do
    jws |> decoded_header_json_to_map() |> empty_header
  end

  defp decoded_header_json_to_map(jws) do
    [head | _] = String.split(jws, ".")
    head
    |> Base.url_decode64!(padding: false)
    |> Poison.decode(keys: :atoms)
    |> header_map
  end

  defp header_map({:ok, map}), do: map
  defp header_map({:error, _}), do: raise "Failed to decode header from JSON"
  defp header_map({:error, _, _}), do: raise "Failed to decode header from JSON"

  defp empty_header(%{}), do: :ok
  defp empty_header(_), do: raise "Header should be empty"

  defp verified(jws, "none", _), do: {:ok, jws}
  defp verified(jws, algorithm, key) do
    verified_jws(jws, signature_verify?(parts_list(jws), algorithm, key))
  end

  defp verified_jws(jws, true), do: {:ok, jws}
  defp verified_jws(_, _), do: {:error, "invalid"}

  defp parts_list(jws), do: valid_parts_list(String.split jws, ".")

  defp valid_parts_list(parts) when length(parts) == @signed_message_parts, do: parts
  defp valid_parts_list(_), do: nil

  defp signature_verify?(nil, _, _), do: false
  defp signature_verify?(_, _, nil), do: false
  defp signature_verify?(parts, algorithm, key) do
    [header, message, signature] = parts
    Jwa.verify?(Base.url_decode64!(signature, padding: false), algorithm, key, "#{header}.#{message}")
  end
end

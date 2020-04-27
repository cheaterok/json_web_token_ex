defmodule JsonWebTokenVivox.Algorithm.EcdsaUtil do
  @moduledoc "Encryption keys for test"

  @doc "Generate an Ecdsa {public_key, private_key} tuple"
  def key_pair(sha_bits \\ :sha256) do
    :crypto.generate_key(:ecdh, JsonWebTokenVivox.Algorithm.Ecdsa.curve(sha_bits))
  end
end

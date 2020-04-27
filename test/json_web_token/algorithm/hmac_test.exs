defmodule JsonWebTokenVivox.Algorithm.HmacTest do
  use ExUnit.Case

  alias JsonWebTokenVivox.Algorithm.Hmac

  doctest Hmac

  @hs256_key "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
  @hs384_key "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS"
  @hs512_key "ysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hc"

  @signing_input_0 "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
  @signing_input_1 "{\"iss\":\"mike\",\"exp\":1300819380,\"http://example.com/is_root\":false}"

  defp detect_changed_input_or_mac(sha_bits, key) do
    mac_0 = Hmac.sign(sha_bits, key, @signing_input_0)
    assert Hmac.verify?(mac_0, sha_bits, key, @signing_input_0)
    refute Hmac.verify?(mac_0, sha_bits, key, @signing_input_1)

    mac_1 = Hmac.sign(sha_bits, key, @signing_input_1)
    refute Hmac.verify?(mac_1, sha_bits, key, @signing_input_0)
    assert Hmac.verify?(mac_1, sha_bits, key, @signing_input_1)
  end

  test "HS256 sign/3 and verify?/4", do: detect_changed_input_or_mac(:sha256, @hs256_key)

  test "HS384 sign/3 and verify?/4", do: detect_changed_input_or_mac(:sha384, @hs384_key)

  test "HS512 sign/3 and verify?/4", do: detect_changed_input_or_mac(:sha512, @hs512_key)

  test "changed key returns verify?/4 false" do
    sha_bits = :sha256
    key_1 = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9Z"
    mac = Hmac.sign(sha_bits, @hs256_key, @signing_input_0)
    assert Hmac.verify?(mac, sha_bits, @hs256_key, @signing_input_0)
    refute Hmac.verify?(mac, sha_bits, key_1, @signing_input_0)
  end

  # param validation
  test "sign/3 w unrecognized sha_bits raises" do
    message = "Invalid sha_bits"
    assert_raise RuntimeError, message, fn ->
      Hmac.sign(:sha257, @hs256_key, @signing_input_0)
    end
  end

  defp invalid_key(sha_bits, key, message \\ "Key size smaller than the hash output size") do
    assert_raise RuntimeError, message, fn ->
      Hmac.sign(sha_bits, key, @signing_input_0)
    end
  end

  test "sign/3 w :sha256 w key nil raises" do
    invalid_key(:sha256, nil, "Param nil")
  end

  test "sign/3 w :sha256 w key empty string raises" do
    invalid_key(:sha256, "", "Param blank")
  end

  test "sign/3 w :sha256 w key length (31) < MAC length (32) raises" do
    invalid_key(:sha256, "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9")
  end

  test "sign/3 w :sha256 w key length == MAC length (32)" do
    mac = Hmac.sign(:sha256, @hs256_key, @signing_input_0)
    assert byte_size(mac) == 32
  end
end

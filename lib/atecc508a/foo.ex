defmodule Foo do
  def construct_mac_message(mode, key_id, challenge, response, other_data) do
    # Validate inputs
    validate_inputs!(mode, key_id, challenge, response, other_data)

    # Construct the MAC message according to ATECC608A specification
    # Message structure (96 bytes total):
    # - Key (32 bytes) - represented as zeros for host-side (actual key is internal)
    # - Challenge (32 bytes)
    # - Response (32 bytes)
    # - Other data (11 bytes)
    # - Mode (1 byte)
    # - Key ID (2 bytes, little endian)

    # 32 bytes of zeros (key is internal to chip)
    key_placeholder = <<0::256>>
    key_id_bytes = <<key_id::little-16>>
    mode_byte = <<mode>>

    # Concatenate all components
    key_placeholder <> challenge <> response <> other_data <> mode_byte <> key_id_bytes
  end

  @doc """
  Constructs MAC message specifically for the MAC command (opcode 0x08).

  ## Parameters

  - `key_id`: Key slot ID (0-15)
  - `challenge`: 32-byte challenge data
  - `session_key`: 32-byte session key (if applicable, otherwise zeros)

  ## Returns

  Binary MAC message for MAC command
  """
  def construct_mac_command_message(key_id, challenge, session_key \\ nil) do
    session_key = session_key || <<0::256>>

    # Other data for MAC command (11 bytes)
    # Opcode (1) + Mode (1) + KeyID (2) + zeros (7)
    other_data = <<0x08, 0x00, key_id::little-16, 0, 0, 0, 0, 0, 0, 0>>

    construct_mac_message(0x00, key_id, challenge, session_key, other_data)
  end

  @doc """
  Constructs MAC message for CheckMAC command (opcode 0x28).

  ## Parameters

  - `key_id`: Key slot ID (0-15)
  - `challenge`: 32-byte challenge data
  - `response`: 32-byte response to verify
  - `other_data`: 13-byte other data field

  ## Returns

  Binary MAC message for CheckMAC command
  """
  def construct_checkmac_message(key_id, challenge, response, other_data)
      when byte_size(other_data) == 13 do
    # For CheckMAC, we need to adjust the message structure
    # 32 bytes
    key_placeholder = <<0::256>>

    # Other data is 13 bytes for CheckMAC
    # CheckMAC mode
    mode_byte = <<0x01>>
    key_id_bytes = <<key_id::little-16>>

    key_placeholder <> challenge <> response <> other_data <> mode_byte <> key_id_bytes
  end

  @doc """
  Computes the SHA-256 hash of the MAC message.
  This is the final digest that would be computed by the ATECC608A.

  ## Parameters

  - `mac_message`: The MAC message binary from construct_mac_message/5

  ## Returns

  32-byte SHA-256 digest
  """
  def compute_digest(mac_message) do
    :crypto.hash(:sha256, mac_message)
  end

  # Private helper functions

  defp validate_inputs!(mode, key_id, challenge, response, other_data) do
    unless is_integer(mode) and mode >= 0 and mode <= 255 do
      raise ArgumentError, "mode must be a byte value (0-255)"
    end

    unless is_integer(key_id) and key_id >= 0 and key_id <= 15 do
      raise ArgumentError, "key_id must be between 0 and 15"
    end

    unless is_binary(challenge) and byte_size(challenge) == 32 do
      raise ArgumentError, "challenge must be exactly 32 bytes"
    end

    unless is_binary(response) and byte_size(response) == 32 do
      raise ArgumentError, "response must be exactly 32 bytes"
    end

    unless is_binary(other_data) and byte_size(other_data) == 11 do
      raise ArgumentError, "other_data must be exactly 11 bytes"
    end
  end
end

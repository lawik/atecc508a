# SPDX-FileCopyrightText: 2018 Frank Hunleth
# SPDX-FileCopyrightText: 2021 Alex McLain
# SPDX-FileCopyrightText: 2022 Jon Carstens
# SPDX-FileCopyrightText: 2023 Connor Rigby
# SPDX-FileCopyrightText: 2024 Serhii Lukianov
# SPDX-FileCopyrightText: 2025 Lars Wikman
#
# SPDX-License-Identifier: Apache-2.0
#
defmodule ATECC508A.Request do
  @moduledoc """
  This module knows how to send requests to the ATECC508A.
  """

  alias ATECC508A.Transport

  require Logger

  @type zone :: :config | :otp | :data
  @type slot :: 0..15
  @type block :: 0..3
  @type offset :: 0..7
  @type access_size :: 4 | 32
  @type access_data :: <<_::32>> | <<_::256>>
  @type addr :: 0..65535

  @typedoc """
  A transaction is a tuple with the binary to send, how long to
  wait in milliseconds for the response and the size of payload to
  expect to read for the response.
  """
  @type transaction :: {binary(), non_neg_integer(), non_neg_integer()}

  @atecc508a_op_read 0x02
  @atecc508a_op_mac 0x08
  @atecc508a_op_write 0x12
  @atecc508a_op_nonce 0x16
  @atecc508a_op_genkey 0x40
  @atecc508a_op_lock 0x17
  @atecc508a_op_random 0x1B
  @atecc508a_op_sign 0x41
  @atecc508a_op_ecdh 0x43
  @atecc508a_op_sha 0x47
  @atecc508a_op_info 0x30
  @atecc508a_op_aes 0x51
  @atecc508a_op_checkmac 0x28
  # TODO:
  # CheckMac 0x28 (unlock volatile key slot)
  #  Info 0x30 mode: 4 (get/set latch)
  # AES 0x51 encrypt/decrypt

  # See https://github.com/MicrochipTech/cryptoauthlib/blob/master/lib/calib/calib_execution.c
  # for command max execution times. I'm not sure why they are different from the
  # datasheet. Since this library is compatible with the ECC608A, the longer time is
  # used.

  @spec to_config_addr(0..127) :: addr()
  def to_config_addr(byte_offset)
      when byte_offset >= 0 and byte_offset < 128 and rem(byte_offset, 4) == 0 do
    div(byte_offset, 4)
  end

  @spec to_config_addr(block(), offset()) :: addr()
  def to_config_addr(block, offset)
      when is_integer(block) and is_integer(offset) and
             block >= 0 and block < 4 and
             offset >= 0 and offset < 8 do
    block * 8 + offset
  end

  @spec to_otp_addr(0..127) :: addr()
  def to_otp_addr(byte_offset), do: to_config_addr(byte_offset)

  @spec to_otp_addr(block(), offset()) :: addr()
  def to_otp_addr(block, offset) when is_integer(block) and is_integer(offset),
    do: to_config_addr(block, offset)

  @spec to_data_addr(slot(), 0..416) :: addr()
  def to_data_addr(slot, byte_offset)
      when slot >= 0 and slot < 16 and byte_offset >= 0 and byte_offset < 416 and
             rem(byte_offset, 4) == 0 do
    word_offset = div(byte_offset, 4)
    offset = rem(word_offset, 8)
    block = div(word_offset, 8)
    to_data_addr(slot, block, offset)
  end

  @spec to_data_addr(slot(), block(), offset()) :: addr()
  def to_data_addr(slot, block, offset)
      when is_integer(slot) and is_integer(block) and is_integer(offset) and
             slot >= 0 and slot < 16 and
             block >= 0 and block < 13 and
             offset >= 0 and offset < 8 do
    block * 256 + slot * 8 + offset
  end

  @doc """
  Create a read message
  """
  @spec read_zone(Transport.t(), zone(), addr(), access_size()) ::
          {:ok, binary()} | {:error, atom()}
  def read_zone(transport, zone, addr, length) do
    payload =
      <<@atecc508a_op_read, length_flag(length)::1, 0::5, zone_index(zone)::2, addr::little-16>>

    transport
    |> transport_request(payload, 5, length)
  end

  @doc """
  Create a write message
  """
  @spec write_zone(Transport.t(), zone(), addr(), access_data()) :: :ok | {:error, atom()}
  def write_zone(transport, zone, addr, data) do
    len = byte_size(data)

    payload =
      <<@atecc508a_op_write, length_flag(len)::1, 0::5, zone_index(zone)::2, addr::little-16,
        data::binary>>

    transport
    |> transport_request(payload, 45, 1)
    |> return_status()
  end

  @doc """
  Create a genkey request message.
  """
  @spec genkey(Transport.t(), slot(), boolean()) :: {:ok, binary()} | {:error, atom()}
  def genkey(transport, key_id, create_key?) do
    mode2 = if create_key?, do: 1, else: 0
    mode3 = 0
    mode4 = 0

    payload =
      <<@atecc508a_op_genkey, 0::3, mode4::1, mode3::1, mode2::1, 0::2, key_id::little-16>>

    transport
    |> transport_request(payload, 653, 64)
  end

  def try(transport) do
    block = 3
    enc = <<137, 91, 20, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232>>
    key_id = 1

    for t <- 20..240 do
      payload = <<0x51, 1::3, 0::3, block::2, key_id::16, enc::binary>>

      # Timeout is arbitrary
      IO.inspect(t)
      result = transport_request(transport, payload, t * 20, 16)
      IO.inspect(result)
    end
  end

  @doc """
  Create a message to lock a zone.
  """
  @spec lock_zone(Transport.t(), zone(), ATECC508A.crc16()) :: :ok | {:error, atom()}
  def lock_zone(transport, zone, zone_crc) do
    # Need to calculate the CRC of everything written in the zone to be
    # locked for this to work.

    # See Table 9-31 - Mode Encoding
    mode = if zone == :config, do: 0, else: 1
    payload = <<@atecc508a_op_lock, mode, zone_crc::binary>>

    transport
    |> transport_request(payload, 35, 1)
    |> return_status()
  end

  @doc """
  Lock a specific slot.
  """
  @spec lock_slot(Transport.t(), slot()) :: :ok | {:error, atom()}
  def lock_slot(transport, slot) do
    # Need to calculate the CRC of everything written in the zone to be
    # locked for this to work.

    # See Table 9-31 - Mode Encoding
    mode = <<0::size(2), slot::size(4), 2::size(2)>>
    payload = <<@atecc508a_op_lock, mode::binary, 0::size(16)>>

    transport
    |> transport_request(payload, 35, 1)
    |> return_status()
  end

  @doc """
  Request a random number.
  """
  @spec random(Transport.t()) :: {:ok, binary()} | {:error, atom()}
  def random(transport) do
    payload = <<@atecc508a_op_random, 0, 0, 0>>

    transport
    |> transport_request(payload, 23, 32)
  end

  @doc """
  Sign a SHA256 digest.
  """
  @spec sign_digest(Transport.t(), slot(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def sign_digest(transport, key_id, digest) do
    Transport.transaction(transport, fn request ->
      # See Table 11-33 - Mode Encoding
      nonce_mode = <<1::size(2), 0::size(1), 0::size(3), 3::size(2)>>

      request.(<<@atecc508a_op_nonce, nonce_mode::binary, 0::size(16), digest::binary>>, 29, 1)
      |> interpret_result()
      |> case do
        {{:ok, _}, _retry} ->
          # See Table 11-50 - Mode Encoding
          sign_mode = <<5::size(3), 0::size(4), 0::size(1)>>

          # datasheet has typical values, recommendation for ATECC608 is up to +50ms
          # we measured 129ms working for 500 attempts without failing
          # 129 base + 50 margin = 179 ms is hopefully plenty
          request.(<<@atecc508a_op_sign, sign_mode::binary, key_id::little-16>>, 179, 64)

        {error, _retry} ->
          error
      end
    end)
  end

  @doc """
  Calculates ECDH secret.
  """
  @spec ecdh(Transport.t(), binary()) :: {:ok, binary()} | {:error, atom()}
  def ecdh(transport, raw_pub_key) do
    payload = <<@atecc508a_op_ecdh, 0, 0, 0, raw_pub_key::binary>>

    transport_request(transport, payload, 998, 32)
  end

  @doc """
  Get TempKey state
  """
  @spec get_tempkey(Transport.t()) :: {:ok, binary()} | {:error, atom()}
  def get_tempkey(transport) do
    payload = <<@atecc508a_op_info, 2, 0, 0>>

    # Timeout is arbitrary
    case transport_request(transport, payload, 200, 4) do
      {:ok, <<no_mac::1, genkey_data::1, gendig_data::1, source_flag::1, key_id::3>>} ->
        {:ok,
         %{
           no_mac: no_mac == 1,
           gen: genkey_data == 1,
           gen_dig: gendig_data == 1,
           source: source_flag == 1,
           key_id: key_id
         }}

      {error, _retry} ->
        error
    end
  end

  @doc """
  Get persistent latch value.
  """
  @spec get_latch(Transport.t()) :: {:ok, binary()} | {:error, atom()}
  def get_latch(transport) do
    payload = <<@atecc508a_op_info, 4, 0, 0>>

    # Timeout is arbitrary
    transport_request(transport, payload, 200, 4)
  end

  @doc """
  Set persistent latch.
  """
  @spec set_latch(Transport.t()) :: {:ok, binary()} | {:error, atom()}
  def set_latch(transport) do
    payload = <<@atecc508a_op_info, 4, <<0::6, 1::1, 1::1>>, 0>>

    # Timeout is arbitrary
    transport_request(transport, payload, 200, 4)
  end

  @doc """
  AES encrypt
  """
  @spec aes_encrypt(Transport.t(), slot(), non_neg_integer(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def aes_encrypt(transport, key_id, block, <<plaintext::binary-size(16)>>) when block < 4 do
    mode = <<
      # bits 6-7: which 16-byte block to use as secret key
      block::2,
      # 3-5: must be zero
      0::3,
      # 0-2: 0 = encrypt
      0::3
    >>

    payload = <<@atecc508a_op_aes, mode::binary, key_id::little-16, plaintext::binary>>
    Logger.info("payload size: #{byte_size(payload)}")

    # Timeout is arbitrary
    Transport.transaction(transport, fn request ->
      # Random cmd
      # Logger.info("Random...")

      # with {:ok, _} <- request.(<<@atecc508a_op_random, 0, 0, 0>>, 23, 32) do
      #   Logger.info("AES encrypt...")
      request.(payload, 1000, 16)
      # end
    end)
  end

  # TODO : not confirmed working
  @doc """
  AES encrypt
  """
  @spec aes_decrypt(Transport.t(), slot(), non_neg_integer(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def aes_decrypt(transport, key_id, block, <<encrypted::binary-size(16)>>) when block < 4 do
    # <<@atecc508a_op_aes, 0::1, 0::1, 1::1, 0::3, block::2, key_id::16, encrypted::binary>>

    mode = <<
      # bits 6-7: which 16-byte block to use as secret key
      block::2,
      # 3-5: must be zero
      0::3,
      # 0-2: 1 = decrypt
      1::3
    >>

    random(transport)

    payload =
      <<@atecc508a_op_aes, mode::binary, key_id::little-16, encrypted::binary>>

    # Timeout is arbitrary
    transport_request(transport, payload, 3000, 16)
  end

  def set_temp_key(transport, bytes) do
    # 1-byte nonce
    nonce_mode = <<
      # tempkey
      0::2,
      # 32 bytes
      0::1,
      # must be zero
      0::3,
      # pass-through mode
      3::2
    >>

    Logger.info("Setting TempKey...")

    transport_request(
      transport,
      <<@atecc508a_op_nonce, nonce_mode::binary, 0::size(16), bytes::binary>>,
      100,
      1
    )
  end

  def nonce_test(transport) do
    bytes = "deadbeefdeadbeefdeadbeefdeadbeef"
    # 1-byte nonce
    nonce_mode = <<
      # tempkey
      0::2,
      # 32 bytes
      0::1,
      # must be zero
      0::3,
      # pass-through mode
      3::2
    >>

    Logger.info("Nonce mode: #{inspect(nonce_mode)}")

    a =
      transport_request(
        transport,
        <<@atecc508a_op_nonce, nonce_mode::binary, 0::size(16), bytes::binary>>,
        100,
        1
      )

    nonce_mode = <<
      # tempkey :: ignored
      0::2,
      # 32 bytes
      0::1,
      # must be zero
      0::3,
      # Generate random nonce
      0::2
    >>

    Logger.info("Nonce mode: #{inspect(nonce_mode)}")

    b =
      transport_request(
        transport,
        <<@atecc508a_op_nonce, nonce_mode::binary, 0::size(16), bytes::binary>>,
        100,
        32
      )

    {a, b}
  end

  def sha(transport, data) do
    init_mode = <<
      0::2,
      0::3,
      0::3
    >>

    init_request = <<@atecc508a_op_sha::8, init_mode::binary, 0::size(16)>>

    fin_mode = <<
      1::1,
      1::1,
      0::3,
      2::3
    >>

    fin_request = <<@atecc508a_op_sha, fin_mode::binary, 0::size(16), data::binary>>

    Transport.transaction(transport, fn r ->
      with {{:ok, <<0>>}, _} <- r.(init_request, 500, 1) |> interpret_result() do
        r.(fin_request, 500, 32)
      end
      |> IO.inspect(label: "SHA result")
    end)
  end

  @doc """
  Sign a SHA256 digest.
  """
  @spec check_mac(Transport.t(), slot(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def check_mac(transport, key_id, key, variant \\ :a) do
    Logger.info("Read zone...")

    {:ok, <<sn0_3::4-bytes, _::4-bytes, sn4_8::5-bytes, _::binary>>} =
      read_zone(transport, :config, 0, 32)

    serial_number = sn0_3 <> sn4_8
    IO.inspect(serial_number, label: "serial")
    <<sn0_1::2-bytes, _::6-bytes, sn8::1-bytes>> = serial_number

    Transport.transaction(transport, fn request ->
      # random_payload = <<@atecc508a_op_random, 0, 0, 0>>
      # Logger.info("Random payload: #{inspect(random_payload)}")

      # random_result =
      #  request.(random_payload, 23, 32)
      #  |> interpret_result()

      # Logger.info("Random result: #{inspect(random_result)}")
      # See Table 11-33 - Mode Encoding
      nonce_mode = <<
        # target -> TempKey
        0::2,
        # 32 bytes
        0::1,
        # must be zero
        0::3,
        # Generate random nonce
        0::2
      >>

      mac_mode = <<
        # must be zero
        0::1,
        # don't do the extra OtherData serial thing
        0::1,
        # must be zero
        0::3,
        # target SourceFlag.Rand
        0::1,
        # Use key from keyId (must be zero for volatile key authorization)
        0::1,
        # Use nonce from TempKey
        1::1
      >>

      <<_::20-bytes>> = rand = "dddddddddddddddddddd"

      Logger.info("Nonce mode: #{inspect(nonce_mode)}")
      # First nonce generates a random nonce to TempKey, sets TempKey.SourceFlag = Rand
      # and returns the random value
      nonce_req_seed = <<@atecc508a_op_nonce, nonce_mode::binary, 0::1, 0::15, rand::binary>>
      nonce_req_nonce = <<@atecc508a_op_nonce, nonce_mode::binary, 1::1, 0::15, rand::binary>>
      #     mac_req = <<@atecc508a_op_mac, mac_mode::binary, key_id::little-16>>

      # {:ok, <<nonce::32-bytes>>} <- rand_to_nonce(rng, rand, nonce_mode)
      with {{:ok, <<rng::32-bytes>>}, _} <- interpret_result(request.(nonce_req_seed, 100, 32)),
           {:ok, <<nonce::32-bytes>>} <- rand_to_nonce(rng, rand, nonce_mode) do
        # {{:ok, <<nonce::32-bytes>>}, _} <-
        #        interpret_result(request.(nonce_req_nonce, 100, 32)) do
        # nonce = rng
        #           {{:ok, <<digest::32-bytes>>}, _} <- interpret_result(request.(mac_req, 1000, 32)) do
        #        Logger.info("Digest A: #{inspect(digest)}")
        Logger.info("Nonce (random): #{inspect(nonce, base: :hex)}")
        {host_msg, other} = build_checkmac_msg(key, nonce, serial_number)
        # both
        # {host_msg, other} = build_checkmac_msg(nonce, nonce, serial_number)
        Logger.info("Host CHECK, msg: #{Base.encode16(host_msg)}")
        # {host_msg, other} =
        #  build_mac_msg(key, nonce, @atecc508a_op_mac, mac_mode, key_id, serial_number)

        host_digest = :crypto.hash(:sha256, host_msg)
        Logger.info("Host CHECK, digest: #{Base.encode16(host_digest)}")

        #       Logger.info("Digest B: #{inspect(host_digest)}")
        #       Logger.info("Same? #{inspect(digest == host_digest)}")

        # other_1 = <<
        #   @atecc508a_op_mac,
        #   mac_mode::binary,
        #   key_id::little-16,
        #   0::24,
        #   0::32,
        #   0::16
        # >>

        # other_2 = <<
        #   0::16,
        #   0::32,
        #   0::24,
        #   key_id::little-16,
        #   mac_mode::binary,
        #   @atecc508a_op_mac
        # >>

        # {msg, other} =
        #   case variant do
        #     :a ->
        #       {<<0::size(2 * 8), sn0_1::binary, 0::size(4 * 8), sn8::binary, 0::size(3 * 8),
        #          0::size(8 * 8), 0::size(4 * 8), nonce::binary, key::binary>>, other_1}

        #     :b ->
        #       {<<key::binary, nonce::binary, 0::size(4 * 8), 0::size(8 * 8), 0::size(3 * 8),
        #          sn8::binary, 0::size(4 * 8), sn0_1::binary, 0::size(2 * 8)>>, other_2}

        #     :c ->
        #       {<<0::size(2 * 8), sn0_1::binary, 0::size(4 * 8), sn8::binary, 0::size(3 * 8),
        #          0::size(8 * 8), 0::size(4 * 8), nonce::binary, key::binary>>, other_2}

        #     :d ->
        #       {<<key::binary, nonce::binary, 0::size(4 * 8), 0::size(8 * 8), 0::size(3 * 8),
        #          sn8::binary, 0::size(4 * 8), sn0_1::binary, 0::size(2 * 8)>>, other_1}
        #   end

        # other = <<0::size(8 * 13)>>

        mode = <<
          # must be zero
          0::5,
          # TempKey.sourceFlag = Rand (0)
          0::1,
          # Use key from keyId (must be zero for volatile key authorization)
          0::1,
          # Use TempKey for both
          # 1::1,
          # Use nonce from TempKey
          1::1
        >>

        Logger.info("CheckMAC with mode: #{inspect(mode)}")

        <<_::81-bytes>> =
          check_req =
          <<@atecc508a_op_checkmac, mode::1-bytes, key_id::little-16, 0::256,
            host_digest::32-bytes, other::binary>>

        request.(
          check_req,
          1000,
          1
        )
        |> tap(fn r ->
          Logger.info("CheckMAC result: #{inspect(r)}")
        end)

        #Logger.info("get temp key")
        #<<_::4-bytes>> = tmp_req = <<@atecc508a_op_info, 2, 0::16>>

        # {{:ok, info}, _} =
        #   request.(tmp_req, 998, 4)
        #   |> interpret_result()

        # Logger.info("TempKey info: #{inspect(info, as: :binary, base: :binary)}")

        # Logger.info("get latch 1")
        # {{:ok, result}, _} = request.(<<@atecc508a_op_info, 4, 0, 0>>, 998, 4)
        # |> interpret_result()
        # Logger.info("Latch 1 info: #{inspect(result, as: :binary, base: :binary)}")

        Logger.info("set latch")
        # <<param2::16>> = <<0::8, 0::6, 1::1, 1::1>>
        <<param2::16>> = <<0::6, 3::2, 0::8>>
        # <<param2::16>> = <<1::1, 0::7, 0::8>>
        <<_::4-bytes>> = latch_req = <<@atecc508a_op_info, 4, param2::16>>
        Logger.info("Latch req: #{inspect(latch_req)}")

        {{:ok, result}, _} =
          request.(latch_req, 998, 4)
          |> interpret_result()

        Logger.info("Latch set info: #{inspect(result, as: :binary, base: :binary)}")

        # Logger.info("get latch 2")

        # {{:ok, result}, _} =
        #   request.(<<@atecc508a_op_info, 4, 0::16>>, 998, 4)
        #   |> interpret_result()

        # Logger.info("Latch 2 info: #{inspect(result, as: :binary, base: :binary)}")

        {:ok, result}
      else
        err ->
          Logger.error("Failed: #{inspect(err)}")
      end
    end)
  end

  def check_nonce(transport) do
    Logger.info("Read zone...")

    {:ok, <<sn0_3::4-bytes, _::4-bytes, sn4_8::5-bytes, _::binary>>} =
      read_zone(transport, :config, 0, 32)

    serial_number = sn0_3 <> sn4_8
    IO.inspect(serial_number, label: "serial")
    <<sn0_1::2-bytes, _::6-bytes, sn8::1-bytes>> = serial_number

    Transport.transaction(transport, fn request ->
      # See Table 11-33 - Mode Encoding
      nonce_mode = <<
        # target -> TempKey
        0::2,
        # 32 bytes
        0::1,
        # must be zero
        0::3,
        # Generate random nonce
        0::2
      >>

      mac_mode = <<
        # must be zero
        0::1,
        # don't do the extra OtherData serial thing
        0::1,
        # must be zero
        0::3,
        # target SourceFlag.Rand
        0::1,
        # Use key from keyId (must be zero for volatile key authorization)
        # 0::1,
        # Use tempkey
        1::1,
        # Use nonce from TempKey
        1::1
      >>

      <<_::20-bytes>> = rand = "deadbeefdeadbeefdead"

      Logger.info("Nonce mode: #{inspect(nonce_mode)}")
      # First nonce generates a random nonce to TempKey, sets TempKey.SourceFlag = Rand
      # and returns the random value
      nonce_req_seed = <<@atecc508a_op_nonce, nonce_mode::binary, 0::1, 0::15, rand::binary>>
      nonce_req_nonce = <<@atecc508a_op_nonce, nonce_mode::binary, 1::1, 0::15, rand::binary>>
      key_id = 1
      mac_req = <<@atecc508a_op_mac, mac_mode::binary, key_id::little-16>>

      with {{:ok, <<rng::32-bytes>>}, _} <- interpret_result(request.(nonce_req_seed, 100, 32)),
           {:ok, <<nonce::32-bytes>>} <- rand_to_nonce(rng, rand, nonce_mode),
           # {{:ok, <<nonce::32-bytes>>}, _} <- interpret_result(request.(nonce_req_nonce, 100, 32)) do
           {{:ok, <<digest::32-bytes>>}, _} <- interpret_result(request.(mac_req, 1000, 32)) do
        #        Logger.info("Digest A: #{inspect(digest)}")
        Logger.info("Nonce (local): #{inspect(nonce, base: :hex)}")
        # Use nonce for both
        {host_msg, other} =
          build_mac_msg(nonce, nonce, @atecc508a_op_mac, mac_mode, key_id, serial_number)

        host_digest = :crypto.hash(:sha256, host_msg)
        Logger.info("Device digest:\n#{Base.encode16(digest)}")
        Logger.info("Host digest:\n#{Base.encode16(host_digest)}")
        Logger.info("Same? #{inspect(digest == host_digest)}")
        {:ok, digest}
      end
    end)
  end

  def aes_test(transport, key) do
    slot = key
    # key = "deadbeefdeadbeef"
    # set_temp_key(transport, key)
    payload = :crypto.strong_rand_bytes(16)

    for block <- 0..3 do
      Logger.warning("Slot: #{slot} Block: #{block}")
      result = aes_encrypt(transport, slot, block, payload)
      # result = aes_encrypt(transport, 0xFFFF, block, payload)

      case result do
        {:ok, <<err::8>>} ->
          Logger.error("Fail: #{inspect(err, base: :hex)}")
          {:error, err}

        {:ok, encrypted} ->
          Logger.warning("OK: #{inspect(result)}")
          result = aes_decrypt(transport, slot, block, encrypted)
          # result = aes_decrypt(transport, 0xFFFF, block, encrypted)
          Logger.warning("result: #{inspect(result == {:ok, payload})}")
          result

        _ ->
          Logger.error("Fail: #{inspect(result)}")
          result
      end
    end
  end

  defp zone_index(:config), do: 0
  defp zone_index(:otp), do: 1
  defp zone_index(:data), do: 2

  defp length_flag(32), do: 1
  defp length_flag(4), do: 0

  @spec transport_request(
          transport :: Transport.t(),
          payload :: binary(),
          timeout :: non_neg_integer(),
          response_payload_len :: non_neg_integer(),
          request_timeout :: non_neg_integer()
        ) :: {:ok, binary()} | {:error, atom()}
  defp transport_request(
         transport,
         payload,
         timeout,
         response_payload_len,
         request_timeout \\ 1000
       ) do
    give_up_time = System.monotonic_time(:millisecond) + request_timeout

    retry_request_with_timeout(
      transport,
      payload,
      timeout,
      response_payload_len,
      give_up_time
    )
  end

  defp retry_request_with_timeout(
         transport,
         payload,
         timeout,
         response_payload_len,
         give_up_time
       ) do
    {result, retry?} =
      transport
      |> Transport.request(payload, timeout, response_payload_len)
      |> interpret_result()

    if retry? do
      Process.sleep(100)

      if System.monotonic_time(:millisecond) > give_up_time,
        do: {:error, {:no_more_retries, result}},
        else:
          retry_request_with_timeout(
            transport,
            payload,
            timeout,
            response_payload_len,
            give_up_time
          )
    else
      result
    end
  end

  defp interpret_result({:ok, data}) when byte_size(data) > 1 do
    {{:ok, data}, false}
  end

  defp interpret_result({:error, reason}), do: {{:error, reason}, true}
  defp interpret_result({:ok, <<0x00>>}), do: {{:ok, <<0x00>>}, false}
  defp interpret_result({:ok, <<0x01>>}), do: {{:error, :checkmac_or_verify_miscompare}, false}
  defp interpret_result({:ok, <<0x03>>}), do: {{:error, :parse_error}, true}
  defp interpret_result({:ok, <<0x05>>}), do: {{:error, :ecc_fault}, true}
  defp interpret_result({:ok, <<0x07>>}), do: {{:error, :self_test_error}, false}
  defp interpret_result({:ok, <<0x08>>}), do: {{:error, :health_test_error}, false}
  defp interpret_result({:ok, <<0x0F>>}), do: {{:error, :execution_error}, false}
  defp interpret_result({:ok, <<0x11>>}), do: {{:error, :no_wake}, true}
  defp interpret_result({:ok, <<0xEE>>}), do: {{:error, :watchdog_about_to_expire}, true}
  defp interpret_result({:ok, <<0xFF>>}), do: {{:error, :crc_error}, true}
  defp interpret_result({:ok, <<unknown>>}), do: {{:error, {:unexpected_status, unknown}}, true}

  defp return_status({:ok, _}), do: :ok
  defp return_status(other), do: other

  defp build_checkmac_msg(key, nonce, serial_number) do
    <<sn0_1::2-bytes, sn2_3::2-bytes, sn4_7::4-bytes, sn8::1-bytes>> = serial_number
    length = 88

    {<<
       key::32-bytes,
       # pad key to 32 bytes
       # 0::size(16 * 8),
       nonce::32-bytes,
       0::size(4 * 8),
       0::size(8 * 8),
       0::size(3 * 8),
       sn8::1-bytes,
       0::size(4 * 8),
       sn0_1::2-bytes,
       0::size(2 * 8)
     >>, <<0::size(13 * 8)>>}

    # {<<
    #    0::size(2 * 8),
    #    sn0_1::2-bytes,
    #    0::size(4 * 8),
    #    sn8::1-bytes,
    #    0::size(3 * 8),
    #    0::size(8 * 8),
    #    0::size(4 * 8),
    #    nonce::32-bytes,
    #    key::16-bytes,
    #    # pad key to 32 bytes
    #    0::size(16 * 8)
    #  >>, <<0::size(13 * 8)>>}
  end

  defp build_mac_msg(key, nonce, opcode, mode, param2, serial_number) do
    # <<sn8::1-bytes-little, sn4_7::4-bytes-little, sn2_3::2-bytes-little, sn0_1::2-bytes-little>> =
    #  serial_number

    # <<sn0_1::2-bytes-little, sn2_3::2-bytes-little, sn4_7::4-bytes-little, sn8::1-bytes-little>> =
    #  serial_number

    <<sn0_1::2-bytes, sn2_3::2-bytes, sn4_7::4-bytes, sn8::1-bytes>> = serial_number
    length = 88

    msg =
      [
        <<
          key::32-bytes
          # pad key to 32 bytes
          # 0::size(16 * 8)
        >>,
        <<nonce::32-bytes>>,
        <<opcode::8>>,
        <<mode::1-bytes>>,
        <<param2::little-16>>,
        <<0::size(8 * 8)>>,
        <<0::size(3 * 8)>>,
        <<sn8::1-bytes>>,
        # <<sn4_7::4-bytes>>,
        <<0::size(4 * 8)>>,
        <<sn0_1::2-bytes>>,
        # <<sn2_3::2-bytes>>
        <<0::size(2 * 8)>>
      ]
      |> IO.iodata_to_binary()

    ^length = byte_size(msg)

    {
      msg,
      # OtherData
      <<_::13-bytes>> = <<
        opcode::8,
        mode::1-bytes,
        param2::little-16,
        0::size(3 * 8),
        sn8::1-bytes,
        0::size(4 * 8),
        sn0_1::2-bytes,
        0::size(2 * 8)
      >>
    }
  end

  defp rand_to_nonce(<<rng::32-bytes>>, <<rand::20-bytes>>, <<nonce_mode::1-bytes>>) do
    msg =
      <<rng::32-bytes, rand::20-bytes, @atecc508a_op_nonce::8, nonce_mode::1-bytes, 0x00::8>>

    Logger.info("Nonce Message: #{inspect(byte_size(msg))}")
    {:ok, :crypto.hash(:sha256, msg)}
  end
end

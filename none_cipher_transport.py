import paramiko
from paramiko.message import Message
# Removed 'b' from this import
from paramiko.common import cMSG_NEWKEYS, DEBUG, MSG_NEWKEYS, cMSG_EXT_INFO

class NoneCipherTransport(paramiko.Transport):
    """
    Custom Transport that allows negotiation of 'none' cipher and 'none' MAC
    in addition to standard algorithms, reusing parent activation methods
    when only standard algorithms are negotiated.
    """
    def __init__(self, sock, *args, **kwargs):
        super().__init__(sock, *args, **kwargs)

        # Add 'none' to preferences and info dicts
        self._preferred_ciphers = tuple(self.preferred_ciphers) + ('none',)
        self._preferred_macs = tuple(self.preferred_macs) + ('none',)

        self._cipher_info.update({
            'none': {
                'class': None, 'mode': None, 'block-size': 8,
                'key-size': 0, 'iv-size': 0, 'is_aead': False,
            }
        })
        self._mac_info.update({
            'none': {'class': None, 'size': 0}
        })

    # Override _get_engine minimally to handle 'none' and delegate others
    def _get_engine(self, name, key, iv=None, operation=None, aead=False):
        if name == 'none':
            return None
        return super()._get_engine(name, key, iv, operation, aead)

    # No need to override _compute_key

    def _activate_inbound(self):
        """
        Activate inbound stream. If 'none' cipher or MAC is used, handle
        it specially. Otherwise, delegate to the parent method.
        """
        # Check if custom handling is needed
        if self.remote_cipher == 'none' or self.remote_mac == 'none':
            # --- Custom 'none' handling logic (needed when 'none' is involved) ---
            self._log(DEBUG, "Activating inbound stream with 'none' algorithm.")

            # --- Cipher Setup ---
            remote_cipher_name = self.remote_cipher
            info = self._cipher_info[remote_cipher_name]
            aead = info.get("is_aead", False)
            block_size = info["block-size"]
            engine = None
            iv_in = None

            if remote_cipher_name != 'none':
                key_size = info["key-size"]
                iv_size = info.get("iv-size", block_size)
                if self.server_mode:
                    iv_in = self._compute_key("A", iv_size)
                    key_in = self._compute_key("C", key_size)
                else:
                    iv_in = self._compute_key("B", iv_size)
                    key_in = self._compute_key("D", key_size)
                engine = self._get_engine( # Our override handles delegation
                    name=remote_cipher_name, key=key_in, iv=iv_in,
                    operation=self._DECRYPT, aead=aead,
                )

            # --- MAC Setup ---
            remote_mac_name = self.remote_mac
            mac_engine = None
            mac_key = None
            mac_size = 16 if aead else 0 # Default for AEAD or 'none'
            etm = False

            if remote_mac_name != 'none' and not aead:
                mac_info = self._mac_info[remote_mac_name]
                mac_size = mac_info["size"]
                mac_engine = mac_info["class"]
                mac_key_len = mac_engine().digest_size
                if self.server_mode:
                    mac_key = self._compute_key("E", mac_key_len)
                else:
                    mac_key = self._compute_key("F", mac_key_len)
                etm = "etm@openssh.com" in remote_mac_name

            # --- Set Packetizer ---
            self.packetizer.set_inbound_cipher(
                block_engine=engine, block_size=block_size,
                mac_engine=mac_engine, mac_size=mac_size, mac_key=mac_key,
                etm=etm, aead=aead, iv_in=iv_in if aead else None,
            )

            # --- Compression ---
            compress_in = self._compression_info[self.remote_compression][1]
            if compress_in is not None and (
                self.remote_compression != "zlib@openssh.com" or self.authenticated
            ):
                self._log(DEBUG, "Switching on inbound compression ...")
                self.packetizer.set_inbound_compressor(compress_in())

            # --- Strict KEX ---
            if self.agreed_on_strict_kex:
                self._log(DEBUG, "Resetting inbound seqno after NEWKEYS due to strict mode")
                self.packetizer.reset_seqno_in()
            # --- End of Custom 'none' Handling ---
        else:
            # Standard algorithms negotiated, reuse parent logic
            self._log(DEBUG, "Activating inbound stream using superclass method.")
            super()._activate_inbound()


    def _activate_outbound(self):
        """
        Activate outbound stream. If 'none' cipher or MAC is used, handle
        it specially. Otherwise, delegate to the parent method.
        """
        # Check if custom handling is needed
        if self.local_cipher == 'none' or self.local_mac == 'none':
             # --- Custom 'none' handling logic (needed when 'none' is involved) ---
            self._log(DEBUG, "Activating outbound stream with 'none' algorithm.")

            m = Message()
            m.add_byte(cMSG_NEWKEYS)
            self._send_message(m)

            if self.agreed_on_strict_kex:
                self._log(DEBUG, "Resetting outbound seqno after NEWKEYS due to strict mode")
                self.packetizer.reset_seqno_out()

            # --- Cipher Setup ---
            local_cipher_name = self.local_cipher
            info = self._cipher_info[local_cipher_name]
            aead = info.get("is_aead", False)
            block_size = info["block-size"]
            engine = None
            iv_out = None
            sdctr = False

            if local_cipher_name != 'none':
                key_size = info["key-size"]
                iv_size = info.get("iv-size", block_size)
                if self.server_mode:
                    iv_out = self._compute_key("B", iv_size)
                    key_out = self._compute_key("D", key_size)
                else:
                    iv_out = self._compute_key("A", iv_size)
                    key_out = self._compute_key("C", key_size)
                engine = self._get_engine( # Our override handles delegation
                    name=local_cipher_name, key=key_out, iv=iv_out,
                    operation=self._ENCRYPT, aead=aead,
                )
                sdctr = local_cipher_name.endswith("-ctr")

            # --- MAC Setup ---
            local_mac_name = self.local_mac
            mac_engine = None
            mac_key = None
            mac_size = 16 if aead else 0 # Default for AEAD or 'none'
            etm = False

            if local_mac_name != 'none' and not aead:
                mac_info = self._mac_info[local_mac_name]
                mac_size = mac_info["size"]
                mac_engine = mac_info["class"]
                mac_key_len = mac_engine().digest_size
                if self.server_mode:
                    mac_key = self._compute_key("F", mac_key_len)
                else:
                    mac_key = self._compute_key("E", mac_key_len)
                etm = "etm@openssh.com" in local_mac_name

            # --- Set Packetizer ---
            self.packetizer.set_outbound_cipher(
                block_engine=engine, block_size=block_size,
                mac_engine=mac_engine, mac_size=mac_size, mac_key=mac_key,
                sdctr=sdctr, etm=etm, aead=aead, iv_out=iv_out if aead else None,
            )

            # --- Compression ---
            compress_out = self._compression_info[self.local_compression][0]
            if compress_out is not None and (
                self.local_compression != "zlib@openssh.com" or self.authenticated
            ):
                self._log(DEBUG, "Switching on outbound compression ...")
                self.packetizer.set_outbound_compressor(compress_out())

            # --- Final Steps (copied from base logic for outbound) ---
            if not self.packetizer.need_rekey():
                self.in_kex = False
            if (
                self.server_mode
                and self.server_sig_algs
                and getattr(self, '_remote_ext_info', None) == "ext-info-c"
            ):
                extensions = {"server-sig-algs": ",".join(self.preferred_pubkeys)}
                m_ext = Message()
                m_ext.add_byte(cMSG_EXT_INFO)
                m_ext.add_int(len(extensions))
                for name, value in sorted(extensions.items()):
                    m_ext.add_string(name)
                    m_ext.add_string(value)
                self._send_message(m_ext)
            self._expect_packet(MSG_NEWKEYS)
            # --- End of Custom 'none' Handling ---
        else:
            # Standard algorithms negotiated, reuse parent logic
            self._log(DEBUG, "Activating outbound stream using superclass method.")
            super()._activate_outbound()
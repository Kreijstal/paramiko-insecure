# ssh_client.py
import socket
import paramiko
import sys
import logging
import time

from logging_config import setup_logging

from none_cipher_transport import NoneCipherTransport

# --- Configuration ---
SERVER_HOST, SERVER_PORT = "127.0.0.1", 2200
USERNAME = "testuser" # Doesn't matter for 'none' auth in our server

# --- Main Client Logic ---
def main():
    setup_logging(level=logging.DEBUG) # Set log level here

    client_socket = None
    transport = None
    channel = None

    try:
        # 1. Establish TCP connection
        logging.info(f"Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        logging.info("TCP connection established.")

        # 2. Set up Custom Transport
        transport = NoneCipherTransport(client_socket)

        transport._preferred_ciphers = ('none',) + tuple(c for c in transport.preferred_ciphers if c != 'none')
        transport._preferred_macs = ('none',) + tuple(m for m in transport.preferred_macs if m != 'none')
        transport.set_gss_host(socket.getfqdn(""))
        logging.warning("Using custom transport with forced 'none' cipher (INSECURE!)")

        # 3. Start Client Session (Key Exchange, Host Key Verification - SKIPPED!)
        logging.info("Starting client protocol negotiation...")
        try:
            # WARNING: We are NOT verifying the host key! This is insecure!
            # In a real client, you MUST verify the host key using known_hosts.
            transport.start_client(timeout=10)
            logging.info("Client negotiation complete.")
            server_key = transport.get_remote_server_key()
            logging.warning(f"Server Host Key received (type={server_key.get_name()}, size={server_key.get_bits()}) - NOT VERIFIED!")

            logging.info(f"Negotiated KEX: {transport.get_security_options().kex[0]}")
            logging.info(f"Negotiated Host Key Alg: {transport.host_key_type}") # Algo used, not the key itself
            logging.info(f"Negotiated Cipher: {transport.local_cipher}")
            logging.info(f"Negotiated MAC: {transport.local_mac}")
            logging.info(f"Negotiated Compression: {transport.local_compression}")

            if transport.local_cipher != 'none' or transport.local_mac != 'none':
                 logging.warning("Could not negotiate 'none' cipher/MAC. Using defaults.")

        except paramiko.SSHException as e:
            logging.error(f"SSH negotiation failed: {e}", exc_info=True)
            # Check if it's specifically a host key issue (it shouldn't be if we didn't provide a policy)
            if isinstance(e, paramiko.BadHostKeyException):
                 logging.error("Server host key is bad (or mismatch if using known_hosts).")
            elif isinstance(e, paramiko.AuthenticationException):
                 logging.error("Authentication failed (unexpected here).")
            return
        except Exception as e:
            logging.error(f"Error during client start: {e}", exc_info=True)
            return

        # 4. Authenticate using "none"
        logging.info(f"Attempting 'none' authentication as user '{USERNAME}'...")
        try:
            transport.auth_none(USERNAME)
            logging.info("Authentication successful (method 'none').")
        except paramiko.AuthenticationException:
            logging.error("Authentication failed (server rejected 'none' or username).")
            return
        except paramiko.SSHException as e:
            logging.error(f"SSH error during authentication: {e}")
            return
        except Exception as e:
            logging.error(f"Unexpected error during authentication: {e}", exc_info=True)
            return

        if not transport.is_authenticated():
            logging.error("Transport is not authenticated after auth attempt.")
            return

        # 5. Open a session channel
        logging.info("Opening session channel...")
        try:
            channel = transport.open_session(timeout=10)
            if channel is None:
                logging.error("Failed to open session channel (server refused or timed out).")
                return
            logging.info(f"Session channel opened: {channel}")
        except Exception as e:
            logging.error(f"Error opening channel: {e}", exc_info=True)
            return

        # 6. Receive data
        logging.info("Waiting to receive data from server...")
        try:
            # Check if channel is active and ready to receive
            while not channel.recv_ready() and not channel.closed:
                if not transport.is_active():
                    logging.error("Transport closed unexpectedly.")
                    return
                logging.debug("Channel not ready to receive, waiting...")
                time.sleep(0.1)

            if channel.recv_ready():
                received_data = channel.recv(1024) # Read up to 1024 bytes
                logging.info(f"Received {len(received_data)} bytes.")
                print("\n--- Received from Server ---")
                try:
                    print(received_data.decode('utf-8'))
                except UnicodeDecodeError:
                    print(f"(Could not decode as UTF-8): {received_data!r}")
                print("---------------------------\n")
            else:
                 logging.warning("Channel closed before receiving data or recv_ready() never became true.")

            # Check exit status if available
            if channel.exit_status_ready():
                exit_status = channel.recv_exit_status()
                logging.info(f"Server exit status: {exit_status}")

        except socket.timeout:
            logging.warning("Timeout waiting for data.")
        except Exception as e:
            logging.error(f"Error receiving data: {e}", exc_info=True)

    except ConnectionRefusedError:
        logging.error(f"Connection refused. Is the server running on {SERVER_HOST}:{SERVER_PORT}?")
        print(f"ERROR: Connection refused. Server not running or firewall blocking {SERVER_PORT}?", file=sys.stderr)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        print(f"ERROR: An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        # 7. Clean up
        if channel and not channel.closed:
            logging.info("Closing channel.")
            channel.close()
        if transport and transport.is_active():
            logging.info("Closing transport.")
            transport.close()
        if client_socket:
            logging.info("Closing socket.")
            client_socket.close()
        logging.info("Client finished.")
        print("--- Client finished. ---")

if __name__ == "__main__":
    main()
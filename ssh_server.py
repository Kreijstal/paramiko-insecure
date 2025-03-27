#ssh_server.py
import socket
import threading
import paramiko
import sys
import logging
import time
import os

from logging_config import setup_logging

# --- Configuration ---
HOST, PORT = "127.0.0.1", 2200
SERVER_KEY_BITS = 2048 # Size for temporary RSA host key

# Generate a temporary host key (don't do this in production!)
# In a real server, load a persistent key.
try:
    host_key = paramiko.RSAKey.generate(SERVER_KEY_BITS)
    print(f"--- Generated temporary {SERVER_KEY_BITS}-bit RSA host key ---")
except ImportError:
    print("ERROR: Cannot generate RSAKey. Is 'cryptography' library installed?")
    sys.exit(1)


# --- Server Interface Implementation ---
class AllowAllServer(paramiko.ServerInterface):
    """A minimal server handler that allows 'none' auth and sends 'Hello World'."""
    def __init__(self):
        self.event = threading.Event() # To signal when auth is complete

    def check_channel_request(self, kind, chanid):
        logging.info(f"Client requested channel kind='{kind}', chanid={chanid}")
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_none(self, username):
        logging.info(f"Auth attempt: username='{username}', method='none'")
        # Allow any user with 'none' authentication
        self.event.set() # Signal that authentication is successful
        return paramiko.AUTH_SUCCESSFUL

    # Optional: Reject other auth methods explicitly
    def check_auth_password(self, username, password):
        logging.info(f"Auth attempt: username='{username}', method='password' (REJECTED)")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        logging.info(f"Auth attempt: username='{username}', method='publickey' (REJECTED)")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        # Important: Only allow 'none'
        logging.info(f"Client asking for allowed auth methods for user '{username}'")
        return "none" # Could also include 'password', 'publickey' if implemented

    def check_channel_shell_request(self, channel):
        # Client wants an interactive shell
        logging.info("Client requested a shell")
        # In this simple case, we just send hello and close immediately after
        # We don't need a real shell. Signal we're ready (though we won't use it)
        self.event.set() # Reuse event or use another one
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        # Client requested a pseudo-terminal
        logging.info("Client requested PTY")
        return True # Allow it, though we won't use it fully

from none_cipher_transport import NoneCipherTransport

# --- Connection Handler Thread ---
def handle_connection(client_socket, client_addr):
    """Handles a single client connection."""
    logging.info(f"Incoming connection from {client_addr}")
    try:
        # Create our custom transport
        transport = NoneCipherTransport(client_socket)
        transport._preferred_ciphers = ('none',) + tuple(c for c in transport.preferred_ciphers if c != 'none')
        transport._preferred_macs = ('none',) + tuple(m for m in transport.preferred_macs if m != 'none')
        transport.set_gss_host(socket.getfqdn("")) # Needed for some KEX algos
        logging.warning("Using custom transport with forced 'none' cipher (INSECURE!)")

        # Add server key
        transport.add_server_key(host_key)
        logging.info("Added temporary server host key.")

        # Create server handler instance
        server_handler = AllowAllServer()

        # Start the SSH server session
        logging.info("Starting server protocol negotiation...")
        try:
            transport.start_server(server=server_handler)
            logging.info("Server negotiation complete.")
            logging.info(f"Negotiated KEX: {transport.get_security_options().kex[0]}")
            logging.info(f"Negotiated Host Key: {transport.host_key_type}")
            logging.info(f"Negotiated Cipher: {transport.remote_cipher}")
            logging.info(f"Negotiated MAC: {transport.remote_mac}")
            logging.info(f"Negotiated Compression: {transport.remote_compression}")

            if transport.remote_cipher != 'none' or transport.remote_mac != 'none':
                 logging.warning("Could not negotiate 'none' cipher/MAC. Using defaults.")

        except paramiko.SSHException as e:
            logging.error(f"SSH negotiation failed: {e}")
            return
        except Exception as e:
            logging.error(f"Error during server start: {e}", exc_info=True)
            return

        # Wait for authentication to complete (max 10 seconds)
        logging.info("Waiting for client authentication...")
        auth_timed_out = not server_handler.event.wait(10)
        if auth_timed_out:
            logging.error("Client did not authenticate in time.")
            return
        logging.info("Client authenticated.")

        # Wait for a channel to be opened (max 10 seconds)
        logging.info("Waiting for client to request a channel...")
        channel = transport.accept(20) # Timeout for accept()
        if channel is None:
            logging.error("Client did not open a channel in time.")
            return
        logging.info(f"Channel opened by client: {channel}")

        # Wait for shell request (optional, needed if client calls invoke_shell)
        # server_handler.event.clear() # Reset event if needed for shell
        # logging.info("Waiting for shell request...")
        # shell_timed_out = not server_handler.event.wait(10)
        # if shell_timed_out:
        #     logging.error("Client did not request shell in time.")
        #     channel.close()
        #     return
        # logging.info("Shell request received (or bypassed).")


        # Send the "Hello World" message
        message = b"Hello World from Paramiko Server!\n"
        logging.info(f"Sending message: {message!r}")
        channel.sendall(message)
        time.sleep(0.1) # Give a moment for data to send

        # Indicate end-of-file and close channel
        logging.info("Sending EOF and closing channel.")
        channel.send_exit_status(0) # Signal normal exit
        channel.shutdown_write() # No more data from server
        channel.close()


    except Exception as e:
        logging.error(f"Exception handling connection from {client_addr}: {e}", exc_info=True)
    finally:
        try:
            if 'transport' in locals() and transport.is_active():
                logging.info("Closing transport.")
                transport.close()
        except Exception as e:
            logging.error(f"Error closing transport: {e}", exc_info=True)
        try:
            logging.info(f"Closing client socket for {client_addr}.")
            client_socket.close()
        except Exception as e:
            logging.error(f"Error closing client socket: {e}", exc_info=True)

# --- Main Server Loop ---
def main():
    setup_logging(level=logging.DEBUG) # Set log level here

    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow address reuse quickly after server restart
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5) # Listen for up to 5 queued connections
        logging.info(f"SSH server listening on {HOST}:{PORT}...")
        print(f"--- SSH Server listening on {HOST}:{PORT} ---")
        print("--- Waiting for connections... Press Ctrl+C to stop. ---")

        while True:
            try:
                client_sock, client_addr = server_socket.accept()
                # Create a new thread to handle this connection
                thread = threading.Thread(target=handle_connection, args=(client_sock, client_addr), daemon=True)
                thread.start()
            except KeyboardInterrupt:
                logging.info("Ctrl+C detected, shutting down.")
                break
            except Exception as e:
                logging.error(f"Error accepting connection: {e}", exc_info=True)

    except Exception as e:
        logging.error(f"Failed to start server: {e}", exc_info=True)
        print(f"ERROR: Failed to start server: {e}", file=sys.stderr)
    finally:
        if server_socket:
            logging.info("Closing server socket.")
            server_socket.close()
        print("--- Server stopped. ---")

if __name__ == "__main__":
    main()
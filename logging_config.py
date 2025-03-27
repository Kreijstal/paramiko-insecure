# logging_config.py
import logging
import sys

def setup_logging(level=logging.DEBUG):
    """Configures detailed logging, especially for Paramiko transport."""
    # Configure the root logger
    # logging.basicConfig(level=level,
    #                     format='%(levelname)-.1s:%(name)s:[%(lineno)d] %(message)s',
    #                     stream=sys.stdout)

    # Be more specific to see Paramiko's detailed transport logs
    log_format = '%(asctime)s %(levelname)-8s [%(name)s (%(lineno)d)] %(message)s'
    logging.basicConfig(level=logging.WARNING, format=log_format, stream=sys.stdout) # Default less noisy

    # Set Paramiko transport logger to DEBUG
    paramiko_transport_logger = logging.getLogger("paramiko.transport")
    paramiko_transport_logger.setLevel(level)

    # Optional: Set other paramiko loggers if needed
    # logging.getLogger("paramiko.client").setLevel(level)
    # logging.getLogger("paramiko.server").setLevel(level)

    # Ensure handler uses the formatter and level
    # If basicConfig wasn't enough, manually add handler:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(log_format))
    # Apply handler only to specific loggers if basicConfig is too broad
    # paramiko_transport_logger.addHandler(handler)
    # paramiko_transport_logger.propagate = False # Prevent double logging if root handler exists

    print(f"--- Logging setup complete. Paramiko transport logs set to {logging.getLevelName(level)} ---")

# Example usage if run directly
if __name__ == "__main__":
    setup_logging()
    logging.debug("Debug message")
    logging.info("Info message")
    logging.warning("Warning message")
    logging.getLogger("paramiko.transport").debug("Paramiko transport debug message")
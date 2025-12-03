import os
from config import Config


class PayloadManager:
    """Responsible solely for managing the content we want to leak."""

    def ensure_payload_exists(self):
        """Creates the dummy file if it does not exist."""
        if not os.path.exists(Config.PAYLOAD_FILE):
            with open(Config.PAYLOAD_FILE, "w") as f:
                f.write("TOP SECRET PROTOCOLS V2\n")
                f.write("To: director@agency.gov\n")
                f.write("Subject: Asset Liquidation\n")
                f.write("The private keys are stored in the S3 bucket: 'doomsday-vault'\n")
                f.write("Access Code: 8822-1199-0000\n")
            print(f"[System] Generated bait file: {Config.PAYLOAD_FILE}")

    def get_payload_reader(self):
        """Returns a file object for reading."""
        return open(Config.PAYLOAD_FILE, "rb")
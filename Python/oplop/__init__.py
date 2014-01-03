import scrypt
import base64
import re


_length = 10


def _raw_hash(label, password):
    """Generate a unique hash from a label and master password."""
    return base64.urlsafe_b64encode(scrypt.hash(password, label))


def create(label, master):
    """Create a password from a label and master password."""
    encoded_label = label.encode("utf-8")
    encoded_master = master.encode("utf-8")
    hash_ = _raw_hash(encoded_label, encoded_master).decode("ascii")
    found = re.search(r"\d+", hash_)
    if not found:
        hash_ = '1' + hash_
    elif found.start() >= _length:
        hash_ = found.group() + hash_

    return hash_[:_length]

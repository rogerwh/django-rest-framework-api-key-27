from django.contrib.auth.hashers import check_password, make_password
from django.utils.crypto import get_random_string


def concatenate(left, right):
    """
    :type left: str
    :type right: str
    :return: str
    """
    return "{}.{}".format(left, right)


def split(concatenated):
    """
    :type concatenated: str
    :return: tuple(str, str)
    """

    # concatenated = "a.b"
    # ("a", ".", "b")
    left, _, right = concatenated.partition(".")
    return left, right


class KeyGenerator:
    def __init__(self, prefix_length=8, secret_key_length=32):
        """
        :type prefix_length: int
        :type secret_key_length: int
        """
        self.prefix_length = prefix_length
        self.secret_key_length = secret_key_length

    def get_prefix(self):
        return get_random_string(self.prefix_length)

    def get_secret_key(self):
        return get_random_string(self.secret_key_length)

    def hash(self, value):
        """
        :type value: str
        :return: str
        """
        return make_password(value)

    def generate(self):
        """
        :return: tuple(str, str, str)
        """
        prefix = self.get_prefix()
        secret_key = self.get_secret_key()
        key = concatenate(prefix, secret_key)
        hashed_key = self.hash(key)
        return key, prefix, hashed_key

    def verify(self, key, hashed_key):
        """
        :type key: str
        :type hashed_key: str
        :return: bool
        """
        return check_password(key, hashed_key)

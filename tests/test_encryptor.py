"""Encryptor tests"""
from faker import Faker
from encryptor import EncyptionManager


def test_encryptor() -> None:
    """Test encryption and decryption"""
    fake = Faker()
    message = bytes(fake.text(), "utf-8")
    manager = EncyptionManager(fake.sentence())

    encrypted = manager.encrypt(message)
    decrypted = manager.decrypt(encrypted)

    assert message == decrypted

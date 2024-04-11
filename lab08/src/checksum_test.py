import unittest
from checksum import getchecksum, validatechecksum


class ChecksumTestCase(unittest.TestCase):
    def test_getchecksum_numbers(self):
        for number in list(range(20)) + [1 << i for i in range(5, 15)]:
            self.assertEqual(getchecksum(int(number).to_bytes(length=2,byteorder='little')), number)

    def test_getchecksum(self):
        self.assertEqual(getchecksum(b"\x01\x00\x02\x00"), 3)
        self.assertEqual(getchecksum(b"\xff\x00\x00\xff"), 2**16 - 1)
        self.assertEqual(getchecksum(b"\xff\xff\x01\x00"), 2**16)
        self.assertEqual(getchecksum(b"\xff\xff\x01\x00", max_checksum_size=16), 0)
        self.assertEqual(getchecksum(b"\x01\x00\x02\x00\x04\x00\x08\x00"), 15)

    def test_validatechecksum(self):
        self.assertFalse(validatechecksum(b"\x00\x00\x00\x00\x00\x00"))
        self.assertTrue(validatechecksum(b"\xff\xff\xff\xff\x00\x00"))
        self.assertFalse(validatechecksum(b"\xff\xff\xff\xef\x00\x00"))
        self.assertFalse(validatechecksum(b"\xff\xff\xff\xff\xab\xcd"))
        self.assertTrue(validatechecksum(b"\x00\xff\xff\xff\xff\x00"))
        self.assertTrue(validatechecksum(b"\x0f\xf0\xff\xff\x10\x08\x20\x04\x40\x02\x80\x01"))


if __name__ == '__main__':
    unittest.main()

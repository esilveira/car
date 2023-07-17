from app.tokens import CareerCenterToken
from copy import copy
from app.gitlab_facade import GitlabAccessToken
from app import tokens
from unittest import TestCase

TEST_TOKEN_STRING = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJnaXRsYWJfYWNjZXNzX3Rva2VuIjoidG"
    "9rZW4iLCJleHAiOjEzNzQzODk1MzQ3Miwic3ViIjoyLCJhdWQiOiJjYXJlZXJjZW50ZXIiL"
    "CJpc3MiOiJjYXJlZXJjZW50ZXIiLCJpYXQiOjN9.OeehPoaLq3u43ALzA3Ypjs_jIJzx9Ui"
    "ygLGazftvKxM")

TEST_TOKEN_SECRET = "dummySecret"

TEST_TOKEN = CareerCenterToken(
    gitlab_access_token=GitlabAccessToken("token"),
    exp=2**37,
    sub=2,
    iat=3
)


class TokensTestCase(TestCase):
    def setUp(self):
        self.token = copy(TEST_TOKEN)

    def test_encode_token(self):
        result = tokens.encode_token(TEST_TOKEN, TEST_TOKEN_SECRET)
        self.assertEqual(result, TEST_TOKEN_STRING)

    def test_decode_token(self):
        result = tokens.decode_token(TEST_TOKEN_STRING,
                                     TEST_TOKEN_SECRET,
                                     token_cls=type(TEST_TOKEN))

        self.assertEqual(result, TEST_TOKEN)

    def test_expired_token(self):
        self.token.exp = 1
        encoded_token = tokens.encode_token(self.token, TEST_TOKEN_SECRET)

        self.assertRaises(ValueError, tokens.decode_token, encoded_token,
                          TEST_TOKEN_SECRET, token_cls=type(TEST_TOKEN))

    def test_wrong_issuer(self):
        self.token.iss = "quim barreiros"

        encoded_token = tokens.encode_token(
            self.token, TEST_TOKEN_SECRET)

        self.assertRaises(ValueError, tokens.decode_token,
                          encoded_token, TEST_TOKEN_SECRET,
                          token_cls=type(TEST_TOKEN))

    def test_wrong_audience(self):
        self.token.aud = "John Doe"

        encoded_token = tokens.encode_token(
            self.token, TEST_TOKEN_SECRET)

        self.assertRaises(ValueError, tokens.decode_token,
                          encoded_token, TEST_TOKEN_SECRET,
                          token_cls=type(TEST_TOKEN))

    def test_wrong_secret(self):
        encoded_token = tokens.encode_token(
            self.token, "reallyDummySecret")

        self.assertRaises(ValueError, tokens.decode_token,
                          encoded_token, TEST_TOKEN_SECRET,
                          token_cls=type(TEST_TOKEN))

    def test_wrong_token_class(self):
        encoded_token = tokens.encode_token(
            self.token, TEST_TOKEN_SECRET)

        self.assertRaises(ValueError, tokens.decode_token,
                          encoded_token, TEST_TOKEN_SECRET,
                          token_cls=tokens.CareerCenterRefreshToken)

    def test_invalid_token(self):
        self.assertRaises(ValueError,
                          tokens.decode_token,
                          "quim barreiros",
                          TEST_TOKEN_SECRET,
                          token_cls=type(TEST_TOKEN))

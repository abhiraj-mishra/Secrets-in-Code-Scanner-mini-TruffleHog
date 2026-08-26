# ============================================================
# FAKE TEST FILE -- FOR SCANNER TESTING ONLY
# None of the values below are real credentials.
# ============================================================

API_KEY = "FAKE_API_KEY_123456789"

password = "FakePassword123"

token = "FAKE_TOKEN_abcdef123456"

github_token = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE12345"

aws_access_key_id = "AKIAFAKEFAKEFAKEFAKE"

aws_secret_access_key = "FAKEsecretFAKEsecretFAKEsecretFAKEsecret"

jwt_example = "eyJFAKEHEADER123.eyJFAKEPAYLOAD456.FAKESIGNATURE789"

secret = "TotallyFakeSecretValue987"

# A random-looking high-entropy string that no regex will catch,
# but the entropy detector should flag it as suspicious.
random_config_value = "aX9$kLm2#pQr8vTz1&wEbN4uYc7"

# Normal code below (should NOT be flagged)
greeting_message = "Hello, this is just a normal string in the code."
count = 42

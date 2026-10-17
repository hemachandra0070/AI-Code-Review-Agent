# backend/test_review.py

from reviewer import review_code

with open(
    "../sample_code/login.py",
    "r"
) as f:

    code = f.read()

result = review_code(code)

print(result)
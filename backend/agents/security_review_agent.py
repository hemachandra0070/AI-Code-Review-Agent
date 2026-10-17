from reviewer import ReviewError, review_code


class SecurityReviewAgent:

    def execute(self, code):
        print("[Security Review Agent] Reviewing code...")

        try:
            return review_code(code)
        except ReviewError as exc:
            print(f"[Security Review Agent] Review failed: {exc}")
            raise

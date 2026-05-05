import string

def assess_password_strength(password):

    score = 0
    feedback = []

    # Length check - this is by far the most important factor
    # We correctly weight length exponentially higher than all other criteria
    length = len(password)
    if length < 8:
        feedback.append("❌ Very short: Passwords shorter than 8 characters are trivially brute forced")
    elif length < 12:
        feedback.append("⚠️ Short: 12 characters or longer is recommended")
        score += 1
    elif length < 16:
        feedback.append("✅ Good length")
        score += 2
    elif length < 24:
        feedback.append("✅ Very good length")
        score +=3
    else:
        feedback.append("✅ Excellent length")
        score +=4


    # Character type checks per assignment requirements
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if has_upper:
        score +=1
        feedback.append("✅ Contains uppercase letters")
    else:
        feedback.append("⚠️ Missing uppercase letters")

    if has_lower:
        score +=1
        feedback.append("✅ Contains lowercase letters")
    else:
        feedback.append("⚠️ Missing lowercase letters")

    if has_digit:
        score +=1
        feedback.append("✅ Contains numbers")
    else:
        feedback.append("⚠️ Missing numbers")

    if has_special:
        score +=1
        feedback.append("✅ Contains special characters")
    else:
        feedback.append("⚠️ Missing special characters")


    # Calculate overall strength rating
    if score <= 2:
        rating = "🔴 VERY WEAK"
    elif score <=4:
        rating = "🟠 WEAK"
    elif score <=6:
        rating = "🟡 MODERATE"
    elif score <=8:
        rating = "🟢 STRONG"
    else:
        rating = "🟢 EXCELLENT"

    return rating, score, feedback


def main():
    print("=" * 60)
    print("🔑 Password Strength Assessor")
    print("Task 3 - Cybersecurity Internship")
    print("Developed by: Olayemi Samson")
    print("=" * 60)
    print()

    while True:
        password = input("Enter password to test: ")

        if not password:
            print("Please enter a password\n")
            continue

        rating, score, feedback = assess_password_strength(password)

        print(f"\nResult: {rating}")
        print(f"Overall Score: {score} / 8")
        print("\nDetailed breakdown:")
        for line in feedback:
            print(f"  {line}")

        print("\n⚠️ Important Limitation Note:")
        print("This score only measures structural complexity. It does NOT check if")
        print("this password has already been leaked, or appears in common password lists.")

        again = input("\nWould you like to test another password? [y/n]: ")
        if again.lower() != 'y':
            print("\n👋 Exiting program")
            break
        print()


if __name__ == "__main__":
    main()

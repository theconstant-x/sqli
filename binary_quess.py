# Guess the alphabet I have in mind, using binary search. The alphabet is between a and z.
# When you submit a guess, I will respond with "Too low", "Too high", or "Correct". Use this information to find the correct letter in as few guesses as possible.
def binary_guess():
    low = ord('a')
    high = ord('z')

    while low <= high:
        mid = (low + high) // 2
        guess = chr(mid)
        print(f"My guess is: {guess}")

        feedback = input("Is my guess too low, too high, or correct? ").strip().lower()

        if feedback == "correct":
            print(f"Yay! I found the letter: {guess}")
            return guess
        elif feedback == "too low":
            low = mid + 1
        elif feedback == "too high":
            high = mid - 1
        else:
            print("Invalid feedback. Please enter 'too low', 'too high', or 'correct'.")

    print("Hmm, something went wrong. I couldn't find the letter.")
    return None

binary_guess()
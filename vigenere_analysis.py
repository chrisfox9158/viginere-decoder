# TOOL IMPORTS
import itertools

# REFERENCES
reference_freq = {
    'a': 7.3,
    'b': 0.9,
    'c': 3.0,
    'd': 4.4,
    'e': 13.0,
    'f': 2.8,
    'g': 1.6,
    'h': 3.5,
    'i': 7.4,
    'j': 0.2,
    'k': 0.3,
    'l': 3.5,
    'm': 2.5,
    'n': 7.8,
    'o': 7.4,
    'p': 2.7,
    'q': 0.3,
    'r': 7.7,
    's': 6.3,
    't': 9.3,
    'u': 2.7,
    'v': 1.3,
    'w': 1.6,
    'x': 0.5,
    'y': 1.9,
    'z': 0.1,
}

# BASIC TOOL FUNCTIONS AND DATA HANDLING
# Letter counter (used later in Index of Coincidence system)
def count_letters(text):
    counts = {}
    for char in text:
        if char.isalpha():
            letter = char.lower()
            current = counts.get(letter, 0)
            counts[letter] = current + 1
    return counts

# Strip non-alphabetic characters and lowercase everything, returning a clean string for analysis
def clean(text):
    cleaned_text = ""
    for character in text:
        if character.isalpha():
            cleaned_text += character.lower()
    return cleaned_text

# BEGIN ANALYSIS
# Find repeated sequences of given length in ciphertext (returns list of distances between repetitions)
def find_repeated_sequences(text, sequence_length):
    # Strip non-alphabetic characters
    cleaned = clean(text)
    # seen: maps each sequence to original location; distances: records distance between original and recent sequence location
    seen = {}
    distances = []
    # Check each chunk of length sequence_length (math: - sequence_length + 1 ensures that last possible chunk is used, while avoiding null value)
    for i in range(len(cleaned) - sequence_length + 1):
        # Grab chunk of length sequence_length, starting at position i
        sequence = cleaned[i:i+sequence_length]
        if sequence in seen:
            # Seen sequence: find distance from first occurence to now
            distance = i - seen[sequence]
            distances.append(distance)
        else:
            # New sequence: store position
            seen[sequence] = i
    return distances

# Take distances from find_repeated_sequences and rank key lengths by how many distances they divide evenly (more distances divided evenly = more likely candidate)
def kasiski_key_lengths(distances, max_key_length):
    counts = {}
    for distance in distances:
        # Test every key length from 2 up to max_key_length; key_length supported if it divides distance without a remainder
        for key_length in range(2, max_key_length + 1):
            if distance % key_length == 0:
                current = counts.get(key_length, 0)
                counts[key_length] = current + 1
    # Sort by highest first
    sorted_lengths = sorted(counts.items(), key=lambda pair: pair[1], reverse=True)
    return sorted_lengths

# Measure how "clustered" a text's letter distribution is; confirm which key length produces English-like distributions (higher value = more likely English)
def index_of_coincidence(text):
    counts = count_letters(text)
    total_letters = sum(counts.values())
    if total_letters < 2:
        return 0.0
    # IoC calculated from sum(letter_count * (letter_count - 1) for each letter) / (total_letters *(total_letters - 1))
    numerator = 0
    for letter_count in counts.values():
        numerator += letter_count * (letter_count - 1)
    index_of_coincidence = numerator / (total_letters * (total_letters - 1))
    return index_of_coincidence

def column_form(text, key_length):
    cleaned_text = clean(text)
    columns = []
    for offset in range(0, key_length):
        columns.append(cleaned_text[offset::key_length])
    return columns

# Determining best key length option from given candidates
def best_key_length(text, candidates):
    # Prepares and runs iterative loop, which tests each candidate provided and stores the strongest candidate as current_best_key_length
    current_best_key_length = None
    current_best_ioc = 0
    for key_length, _ in candidates:
        # Splits the text into "columns" based on the keylength, allowing for IoC testing of each column (more accurate than full-text analysis)
        columns = column_form(text, key_length)
        average_ioc = sum(index_of_coincidence(column) for column in columns) / len(columns)
        if average_ioc > current_best_ioc:
            current_best_ioc = average_ioc
            current_best_key_length = key_length
    return current_best_key_length

# The full frequency analysis tool that takes an input and returns a chi-square value
def chi_square(text):
    counts = count_letters(text)

    # The percentage calculator, using the pairs from counts (calls counts.items()) given the total number of alphabetic characters (sum of all the number values in counts)
    total = sum(counts.values())
    if total == 0:
        return float("inf")
    percentages = {}

    for letter, count in counts.items():
        percentages[letter] = (count / total) * 100

    # chi-square calculation from percentages, using values from reference_freq and percentages (defaulting to 0 for unused letters) in the ((observed - expected) ** 2 / expected) equation form
    chi_square_total = 0
    for letter, expected_percent in reference_freq.items():
        observed_percent = percentages.get(letter, 0)
        chi_square_total += ((observed_percent - expected_percent) ** 2) / expected_percent

    return chi_square_total

# Simple decoder for caesar cipher given the ciphertext and shift
def caesar_decode(text, shift):
    shift_result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                base = ord('A')
            else:
                base = ord('a')
            shifted = (ord(char) - base + shift) % 26 + base
            shift_result += chr(shifted)
        else:
            shift_result += char
    return shift_result

# This tool uses given key_length and maximum_pairs (amount of (shift, score) pairs retained per column position)
# This tool creates a list of top (shift, score) pairs (formatted as lists holding strongest pairs per column position) for use in the best_results_from_key function
def find_top_shifts(text, key_length, maximum_pairs):
    columns = column_form(text, key_length)
    all_top_shifts = []
    for column in columns:
        column_scores = []
        for shift in range(26):
            decoded_result = caesar_decode(column, -shift)
            chi_square_score = chi_square(decoded_result)
            column_scores.append((shift, chi_square_score))
        sorted_column_scores = sorted(column_scores, key=lambda pair: pair[1])
        top_shifts = sorted_column_scores[:maximum_pairs]
        all_top_shifts.append(top_shifts)
    return all_top_shifts

# Combines top shift candidates per column into full key guesses, scoring each by chi-square
def best_results_from_key(text, top_shift_lists, maximum_pairs, maximum_key_results):
    results = []
    # Fast-path strategy: if one pair allowed per column, avoids combinatorial explosion
    if maximum_pairs == 1:
        shifts = [top_shifts[0][0] for top_shifts in top_shift_lists]
        known_key = ''.join(chr(shift + ord('a')) for shift in shifts)
        decoded = vigenere_decode(text, known_key)
        return [(known_key, decoded, chi_square(decoded))]
    for combination in itertools.product(*top_shift_lists):
        shifts = []
        for shift, score in combination:
            shifts.append(shift)
        known_key = ''.join(chr(shift + ord('a')) for shift in shifts)
        decoded_text = vigenere_decode(text, known_key)
        decoded_text_chi_square_score = chi_square(decoded_text)
        results.append((known_key, decoded_text, decoded_text_chi_square_score))
    sorted_results = sorted(results, key=lambda pair: pair[2])
    best_decoding_results = sorted_results[:maximum_key_results]
    return best_decoding_results

# vigenere decoder using known key; cycles through each position and character, following vigenere algorithm; maintains positional cases of original text
def vigenere_decode(text, known_key):
    key_index = 0
    result = ""
    for character in text:
        if character.isalpha():
            key_character = known_key[key_index % len(known_key)]
            shift = ord(key_character) - ord('a')
            if character.isupper():
                base = ord('A')
            else:
                base = ord('a')
            result_value = (ord(character) - base - shift) % 26 + base
            result += chr(result_value)
            key_index += 1
        else:
            result += character
    return result

# Check if key is a repeated pattern; simplify if necessary
def minimal_key(key):
    for length in range(1, len(key) // 2 + 1):
        if len(key) % length == 0:
            if key[:length] * (len(key) // length) == key:
                return key[:length]
    return key

# INPUT / WIRING FUNCTIONS
ciphertext = input("Enter ciphertext: ")
print("-" * 60)

raw_sequence_length = input("Enter sequence length (press enter for recommended: 3): ")
try:
    sequence_length = int(raw_sequence_length) if raw_sequence_length.strip() else 3
except ValueError:
    sequence_length = 3

distances = find_repeated_sequences(ciphertext, sequence_length)

raw_maximum_key_length = input("Enter maximum key length (press enter for recommended: 20): ")
try:
    maximum_key_length = int(raw_maximum_key_length) if raw_maximum_key_length.strip() else 20
except ValueError:
    maximum_key_length = 20

candidates = kasiski_key_lengths(distances, maximum_key_length)
if not candidates:
    candidates = [(key_length, 0) for key_length in range(2, maximum_key_length + 1)]

raw_maximum_candidates_per_iteration = input("Enter number of candidates used per iteration (press enter for recommended: 10): ")
try:
    candidates_per_iteration_count = int(raw_maximum_candidates_per_iteration) if raw_maximum_candidates_per_iteration.strip() else 10
except ValueError:
    candidates_per_iteration_count = 10
if candidates_per_iteration_count < 1:
    candidates_per_iteration_count = 1
candidates_per_iteration = candidates[:candidates_per_iteration_count]

key_length = best_key_length(ciphertext, candidates_per_iteration)

raw_maximum_pairs = input("Enter maximum pairs (press enter for recommended: 1): ")
try:
    maximum_pairs = int(raw_maximum_pairs) if raw_maximum_pairs.strip() else 1
except ValueError:
    maximum_pairs = 1

# Confirmation message for high-demand combinations (large key length & high # of shifts per position)
if (maximum_pairs >= 3 and key_length > 15) or (maximum_pairs >= 5 and key_length > 10):
    confirm = input("High-demand request (likely: expansive parameter combination). Proceed? Press y to continue: ")
    if confirm.lower() not in ["y", "yes"]:
        print("Aborted.")
        exit()

raw_maximum_key_results = input("Enter maximum key results (press enter for recommended: 5): ")
try:
    maximum_key_results = int(raw_maximum_key_results) if raw_maximum_key_results.strip() else 5
except ValueError:
    maximum_key_results = 5

top_shift_lists = find_top_shifts(ciphertext, key_length, maximum_pairs)
best_decoding_results = best_results_from_key(ciphertext, top_shift_lists, maximum_pairs, maximum_key_results)

# MAIN OUTPUT PRINTING
print("-" * 60)
print("Distances between chunks: ", distances)
print("Key Length Candidates: ", candidates)
print("Probable key length: ", key_length)
print("-" * 60)
print(" " * 21, "DECODE COMPLETE!")
print("-" * 60)
for known_key, decoded_text, score in best_decoding_results:
    print(f"Key used:                {minimal_key(known_key)}")
    print(f"Chi-squared score:       {score:.2f}  (<50 strong, <20 excellent)")
    print(f"\n{decoded_text}\n")
    print("-" * 60)
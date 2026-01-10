from tkinter import filedialog, Tk, simpledialog
import os
import imagehash
from PIL import Image

# Path where your natural image database is stored
IMAGE_DB = "image_database"

# Step 1: Build mapping of images -> hash codes
def build_image_mapping():
    mapping = {}
    
    for img_file in os.listdir(IMAGE_DB):
        if img_file.endswith(".png"):
            img_path = os.path.join(IMAGE_DB, img_file)
            h = imagehash.phash(Image.open(img_path))  # perceptual hash
            mapping[str(h)[:8]] = img_file
    return mapping

# Step 2: Hide text as a sequence of images
def hide_message(message):
    mapping = build_image_mapping()
    bits = ''.join(format(ord(c), '08b') for c in message)  # convert text -> binary
    chunks = [bits[i:i+8] for i in range(0, len(bits), 8)]

    encoded_images = []
    for chunk in chunks:
        # Find an image whose hash ends with those bits (toy example)
        for h, fname in mapping.items():
            if h[-8:] == chunk:
                encoded_images.append(fname)
                break

    print("Message hidden as sequence of images:", encoded_images)
    return encoded_images

# Step 3: Reveal text from sequence of images
def reveal_message(image_sequence):
    mapping = build_image_mapping()
    reverse_map = {v: k for k, v in mapping.items()}

    bits = ""
    for img in image_sequence:
        h = reverse_map[img]
        bits += h[-8:]

    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    message = ''.join(chars)
    print("Recovered message:", message)
    return message


# Example usage
def main():
    root = Tk()
    root.withdraw()

    choice = simpledialog.askstring("Choose Option", "Enter: hide / reveal / exit").lower()
    if choice == "hide":
        msg = simpledialog.askstring("Secret Message", "Enter message to hide")
        hide_message(msg)
    elif choice == "reveal":
        seq = simpledialog.askstring("Reveal", "Enter image filenames separated by commas").split(",")
        reveal_message([s.strip() for s in seq])

main()
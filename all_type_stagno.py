from tkinter import filedialog, Tk, simpledialog
from PIL import Image
import os
import shutil

# Hide a file inside a PNG image using LSB-style appending
def hide_file():
    # Select cover image
    cover_image = filedialog.askopenfilename(title="Select PNG Image as Cover", filetypes=[("PNG Images", "*.png")])
    if not cover_image:
        print("No cover image selected.")
        return

    # Select file to hide
    file_to_hide = filedialog.askopenfilename(title="Select File to Hide")
    if not file_to_hide:
        print("No file selected.")
        return

    # Output file name
    output_image = cover_image.replace(".png", "_with_hidden.png")

    with open(cover_image, "rb") as img_file, open(file_to_hide, "rb") as secret_file:
        image_data = img_file.read()
        secret_data = secret_file.read()

    # Add a marker and file extension to help in extraction
    filename = os.path.basename(file_to_hide)
    marker = b"::HIDDEN_FILE::" + filename.encode() + b"::"
    combined = image_data + marker + secret_data

    with open(output_image, "wb") as out_file:
        out_file.write(combined)

    print(f"File hidden successfully in {output_image}")


# Reveal the hidden file from the image
def reveal_file():
    stego_image = filedialog.askopenfilename(title="Select Image with Hidden File", filetypes=[("PNG Images", "*.png")])
    if not stego_image:
        print("No image selected.")
        return

    with open(stego_image, "rb") as f:
        content = f.read()

    marker_start = content.find(b"::HIDDEN_FILE::")
    if marker_start == -1:
        print("No hidden file found.")
        return

    # Extract file name and data
    name_end = content.find(b"::", marker_start + 15)
    file_name = content[marker_start + 15:name_end].decode()
    file_data = content[name_end + 2:]

    # Save extracted file
    output_path = os.path.join(os.path.expanduser("~"), "Desktop/stagno/extracted files", f"extracted_{file_name}")
    with open(output_path, "wb") as out:
        out.write(file_data)

    print(f"Hidden file extracted to: {output_path}")


# GUI Menu
def main():
    root = Tk()
    root.withdraw()

    while True:
        choice = simpledialog.askstring("Choose Option", "Enter: hide / reveal / exit").lower()
        if choice == "hide":
            hide_file()
        elif choice == "reveal":
            reveal_file()
        elif choice == "exit":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Try again.")

main()
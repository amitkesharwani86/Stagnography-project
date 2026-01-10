import os
from stegano import lsb
from tkinter import filedialog, Tk, simpledialog

# ------------------ STEGANOGRAPHY FUNCTIONS ------------------
def hide_message():
    input_image = filedialog.askopenfilename(title="Select Image to Hide Message")
    if not input_image:
        print("No image selected.")
        return

    message = simpledialog.askstring("Input", "Enter the message to hide:")
    if not message:
        print("No message entered.")
        return

    output_image = input_image.replace(".png", "_encoded.png")
    lsb.hide(input_image, message).save(output_image)

    print(f"Message hidden in {output_image}")


def reveal_message():
    encoded_image = filedialog.askopenfilename(title="Select Encoded Image")
    if not encoded_image:
        print("No image selected.")
        return

    message = lsb.reveal(encoded_image)
    if message:
        print(f"Hidden Message: {message}")
    else:
        print("No hidden message found.")


# ------------------ MAIN APPLICATION ------------------
def main():
    root = Tk()
    root.withdraw()  # Hide main window

    while True:
        choice = simpledialog.askstring("Steganography", "Choose an option:\n1. Hide a Message\n2. Reveal a Message\n3. Exit")
        if choice == '1':
            hide_message()
        elif choice == '2':
            reveal_message()
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

    print("Goodbye!")


if __name__ == '__main__':
    main()

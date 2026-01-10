import speech_recognition as sr
import pyttsx3
import os
from stegano import lsb
from tkinter import filedialog, Tk, simpledialog

# text-to-speech 
engine = pyttsx3.init()

# recognizer
recognizer = sr.Recognizer()

print("This is Program of Steganography .")
engine.say("this is Program of Steganography . ")
engine.runAndWait()

print("Steganography is the practice of hiding secret information within a non-secret file or message to avoid detection. For example, hiding text inside an image or audio file so that it looks normal but contains hidden data.")
engine.say("Steganography is the practice of hiding secret information within a non-secret file or message to avoid detection. For example, hiding text inside an image or audio file so that it looks normal but contains hidden data.")
engine.runAndWait()

# Hide file 
def hide_file():
    # Select cover image
    engine.say("select image in which you want to hide")
    engine.runAndWait()
    cover_image = filedialog.askopenfilename(title="Select PNG Image as Cover", filetypes=[("PNG Images", "*.png")])
    if not cover_image:
        print("No cover image selected.")
        return

    # Select file to hide
    engine.say("select file to hide")
    engine.runAndWait()
    file_to_hide = filedialog.askopenfilename(title="Select File to Hide")
    if not file_to_hide:
        print("No file selected.")
        return

    # Output file name
    output_image = cover_image.replace(".png", "_with_hidden.png")

    with open(cover_image, "rb") as img_file, open(file_to_hide, "rb") as secret_file:
        image_data = img_file.read()
        secret_data = secret_file.read()

    # Add a marker and file extension 
    filename = os.path.basename(file_to_hide)
    marker = b"::HIDDEN_FILE::" + filename.encode() + b"::"
    combined = image_data + marker + secret_data

    with open(output_image, "wb") as out_file:
        out_file.write(combined)

    print(f"File hidden successfully in {output_image}")
    engine.say(f"File hidden successfully \n")
    engine.runAndWait()

# Reveal file
def reveal_file():
    engine.say("select image from which you want to reveal file")
    engine.runAndWait()
    stego_image = filedialog.askopenfilename(title="Select Image with Hidden File", filetypes=[("PNG Images", "*.png")])
    if not stego_image:
        print("No image selected.")
        return

    with open(stego_image, "rb") as f:
        content = f.read()

    marker_start = content.find(b"::HIDDEN_FILE::")
    if marker_start == -1:
        print("No hidden file found.")
        engine.say("no hidden file found")
        engine.runAndWait()
        return

    # Extract file name and data
    name_end = content.find(b"::", marker_start + 15)
    file_name = content[marker_start + 15:name_end].decode()
    file_data = content[name_end + 2:]

    # Save extracted file
    output_path = os.path.join(os.path.expanduser("~"), "Desktop/stagno", f"extracted_{file_name}")
    with open(output_path, "wb") as out:
        out.write(file_data)

    print(f"Hidden file extracted to: {output_path}")
    engine.say("hidden file extracted succesfully\n")
    engine.runAndWait()

# hide text in an image
def hide_message():
    input_image = filedialog.askopenfilename(title="Select Image to Hide Message")
    if not input_image:
        print("No image selected.")
        return
    engine.say("Enter the message you want to hide:")
    engine.runAndWait()
    message = simpledialog.askstring("Input", "Enter the message to hide:")
    if not message:
        print("No message entered.")
        return

    output_image = input_image.replace(".png", "_encoded.png")
    lsb.hide(input_image, message).save(output_image)

    print(f"Message hidden in {output_image}")
    print("Your message hidded succesfully")
    engine.say("Your message hidded succesfully")
    engine.runAndWait()


def reveal_message():
    encoded_image = filedialog.askopenfilename(title="Select Encoded Image")
    if not encoded_image:
        print("No image selected.")
        return

    message = lsb.reveal(encoded_image)
    if message:
        print(f"Hidden Message: {message}\n\n")
        engine.say("your hidden message is")
        engine.runAndWait()
        engine.say(message)
        engine.runAndWait()
    else:
        print("No hidden message found.")


while(True):
    try:
        with sr.Microphone() as source:

            print("what do you want to do? \nHide message \nhide file \nShow message  \nshow file \nExit\n")
            engine.say("what do you want to do?")
            engine.runAndWait()
            engine.say("Hide message ,hide file ,show message ,show file or Exit")
            engine.runAndWait()

            print("Listening...")
            recognizer.adjust_for_ambient_noise(source, duration=1)
            audio = recognizer.listen(source)

        # Google Web Speech API
            text = recognizer.recognize_google(audio).lower()

            print("You said:", text)
            if "exit" in text:
                print("you asked me to exit your program")
                engine.say("you asked me to exit your program")
                engine.runAndWait()
                # print("Exiting your programe")
                engine.say("Exiting your program")
                engine.runAndWait()
                break
            elif "hide message" in text:
                hide_message()
            elif "show message" in text:
                reveal_message()
            elif "hide file" in text:
                hide_file()
            elif"show file" in text:
                reveal_file()

            print("Do you want to do more operation.")
            engine.say("Do you want to do more operation")
            engine.runAndWait()
            print("Listening...")
            recognizer.adjust_for_ambient_noise(source, duration=1)
            audio = recognizer.listen(source)
            text = recognizer.recognize_google(audio).lower()
            if "yes" in text:
                continue
            else:
                print("Exiting Program")
                engine.say("Exiting Program")
                engine.runAndWait() 
                break

    except sr.UnknownValueError:
        print("Sorry, I could not understand the audio.")
        engine.say("Sorry, I could not understand the audio.")
        engine.runAndWait()

    except sr.RequestError as e:
        print(f"Could not request results from Google Speech Recognition service; {e}")
        engine.say("Could not connect to the speech recognition service.")
        engine.runAndWait()
import speech_recognition as sr
import pyttsx3
import os
from stegano import lsb
from tkinter import filedialog, Tk, simpledialog

# Initialize the text-to-speech engine
engine = pyttsx3.init()

# Initialize the recognizer
recognizer = sr.Recognizer()

print("This is Program of Steganography .")
engine.say("this is Program of Steganography . ")
engine.runAndWait()

print("Steganography is the practice of hiding secret information within a non-secret file or message to avoid detection. For example, hiding text inside an image or audio file so that it looks normal but contains hidden data.")
engine.say("Steganography is the practice of hiding secret information within a non-secret file or message to avoid detection. For example, hiding text inside an image or audio file so that it looks normal but contains hidden data.")
engine.runAndWait()

# Function to hide text in an image
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

            print("what do you want to do? \nHide message \nShow message \nExit")
            engine.say("what do you want to do?")
            engine.runAndWait()
            engine.say("Hide message , show message or Exit")
            engine.runAndWait()

            print("Listening...")
            recognizer.adjust_for_ambient_noise(source, duration=1)
            audio = recognizer.listen(source)

        # Recognize speech using Google Web Speech API
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
            elif "hide " in text:
                hide_message()
            elif "show " in text:
                reveal_message()

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
                break

    except sr.UnknownValueError:
        print("Sorry, I could not understand the audio.")
        engine.say("Sorry, I could not understand the audio.")
        engine.runAndWait()

    except sr.RequestError as e:
        print(f"Could not request results from Google Speech Recognition service; {e}")
        engine.say("Could not connect to the speech recognition service.")
        engine.runAndWait()
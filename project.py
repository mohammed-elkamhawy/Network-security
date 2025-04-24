import os
from tkinter import Tk, Label, Button, Entry, filedialog, PhotoImage
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Function to display an image in the label
def display_image(image_path):
    if image_path:
        try:
            image = PhotoImage(file=image_path)  # Open image using PhotoImage
            label_image.config(image=image)
            label_image.image = image  # Keep a reference to avoid garbage collection
        except Exception as e:
            print(f"Error displaying image: {e}")  # Handle potential errors

# Function to encrypt an image using AES
def encrypt_image(image_path, key, output_folder="encrypted_images"):
    with open(image_path, 'rb') as f:
        image_data = f.read()

    # Generate a random initialization vector (IV)
    iv = get_random_bytes(AES.block_size)

    # Create the AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the image data to a multiple of the block size
    pad = AES.block_size - len(image_data) % AES.block_size
    padded_data = image_data + bytes([pad] * pad)

    # Encrypt the padded image data
    encrypted_data = cipher.encrypt(padded_data)

    # Create the output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)  # Handles existing folder gracefully

    # Save the encrypted data with the IV prepended
    output_path = os.path.join(output_folder, f"{os.path.basename(image_path)}")
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)

# Function to decrypt an image using AES
def decrypt_image(encrypted_image_path, key, output_path):
    with open(encrypted_image_path, 'rb') as f:
        encrypted_data = f.read()

    # Extract the IV from the beginning of the encrypted data
    iv = encrypted_data[:AES.block_size]

    # Create the AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the encrypted data
    decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])

    # Remove the padding from the decrypted data
    padding = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding]

    # Save the decrypted image data
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

def select_image_button_click():
    global selected_image_path
    image_path = filedialog.askopenfilename(
        initialdir=".",
        title="Select Image",
        filetypes=[("Image Files", "*.jpg;*.jpeg;*.png")] 
    )
    selected_image_path = image_path
    display_image(selected_image_path)  # Update the displayed image

# Function to handle the encryption process
def encrypt_button_click():
    global selected_image_path
    if selected_image_path:
        key = entry_key.get().encode('utf-8')  # Ensure key is a byte string
        output_path = os.path.join(os.path.dirname(selected_image_path), f"encrypted_{os.path.basename(selected_image_path)}")

        # Hide the original image (optional, security best practice)
        new_image_path = os.path.join(os.path.dirname(selected_image_path), f"{os.path.basename(selected_image_path)}.hidden")
        os.rename(selected_image_path, new_image_path)  # Rename to hide

        try:
            encrypt_image(new_image_path, key, output_path)  # Use hidden path
            label_status.config(text="Image Encrypted Successfully!", fg="green")
            # Delete the original image after successful encryption
            os.remove(new_image_path)  # Remove the hidden file
        except Exception as e:
            label_status.config(text=f"Encryption Error: {str(e)}", fg="red")

# Function to handle the decryption process
def decrypt_button_click():
  hidden_image_path = filedialog.askopenfilename(
      initialdir=".",
      title="Select Hidden Encrypted Image",
      filetypes=[("Hidden Encrypted Files", "*.hidden")]  # Custom extension (optional)
  )

  if hidden_image_path:
    key = entry_key.get().encode('utf-8')  # Ensure key is a byte string

    # Extract filename without extension (assuming ".hidden")
    filename, _ = os.path.splitext(os.path.basename(hidden_image_path))

    # Define a folder for decrypted images (create if it doesn't exist)
    decrypted_folder = "decrypted_images"
    os.makedirs(decrypted_folder, exist_ok=True)

    # Define output path for decrypted image within the folder
    output_path = os.path.join(decrypted_folder, f"{filename}")

    try:
      decrypt_image(hidden_image_path, key, output_path)
      label_status.config(text="Image Decrypted Successfully!", fg="green")
    except Exception as e:
      label_status.config(text=f"Decryption Error: {str(e)}", fg="red")



root = Tk()
root.title("Image Encryption/Decryption")

# Label to display the image
label_image = Label(root)
label_image.pack()

# Button for selecting an image
select_image_button = Button(root, text="Select Image", command=select_image_button_click)
select_image_button.pack()

# Label for key input
label_key = Label(root, text="Enter Key (16 characters):")
label_key.pack()

# Entry field for key input
entry_key = ttk.Entry(root, width=30, show="*")  # Adjust width for key length
entry_key.pack()

# Button for encryption
encrypt_button = Button(root, text="Encrypt Image", command=encrypt_button_click)
encrypt_button.pack()

# Button for decryption
decrypt_button = Button(root, text="Decrypt Image", command=decrypt_button_click)
decrypt_button.pack()

# Label for status messages
label_status = Label(root, text="")
label_status.pack()

# Run the main application loop
root.mainloop()

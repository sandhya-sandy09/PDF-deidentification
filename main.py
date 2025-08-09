import os
import cv2
import pytesseract
from pdf2image import convert_from_path
from PIL import Image
import re
import numpy as np  # moved here

# Path to Tesseract executable
pytesseract.pytesseract.tesseract_cmd = r"C:\Users\Sandhya\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"

# ========= 1. Detect file type =========
def detect_file_type(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in ['.png', '.jpg', '.jpeg']:
        return "image"
    elif ext == '.pdf':
        return "pdf"
    else:
        raise ValueError(f"Unsupported file type: {ext}")

# ========= 2. Pattern matching =========
def is_sensitive(text):
    """
    Define patterns for sensitive data.
    You can expand this list as needed.
    """
    patterns = [
        r"\b\d{2,4}[-/]\d{2,4}[-/]\d{2,4}\b",  # Dates like 2023-08-09 or 09/08/2023
        r"\b\d{10}\b",                         # Phone numbers (10 digits)
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", # Emails
        r"\b[A-Z]{2}\d{6}\b"                   # Example: Passport-like IDs e.g. AB123456
    ]
    for pat in patterns:
        if re.search(pat, text):
            return True
    return False

# ========= 3. Blackout sensitive text in an image =========
def blackout_sensitive_data(image):
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    for i in range(len(data['text'])):
        word = data['text'][i]
        if word.strip() and is_sensitive(word):
            x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
            # Draw solid black rectangle over sensitive text
            cv2.rectangle(image, (x, y), (x + w, y + h), (0, 0, 0), thickness=-1)
    return image

# ========= 4. OCR and blackout for images =========
def process_image(file_path, output_path):
    image = cv2.imread(file_path)
    image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    blacked_out_image = blackout_sensitive_data(image_rgb)
    cv2.imwrite(output_path, cv2.cvtColor(blacked_out_image, cv2.COLOR_RGB2BGR))
    text = pytesseract.image_to_string(blacked_out_image)
    return text

# ========= 5. OCR and blackout for PDFs =========
def process_pdf(file_path, output_folder):
    poppler_path = r"C:\Users\Sandhya\Downloads\Release-24.08.0-0\poppler-24.08.0\Library\bin"
    pages = convert_from_path(file_path, poppler_path=poppler_path)
    all_text = ""
    for idx, page in enumerate(pages):
        page_rgb = page.convert('RGB')
        open_cv_image = cv2.cvtColor(np.array(page_rgb), cv2.COLOR_RGB2BGR)
        blacked_out_image = blackout_sensitive_data(cv2.cvtColor(open_cv_image, cv2.COLOR_BGR2RGB))
        output_path = os.path.join(output_folder, f"page_{idx+1}_blacked_out.png")
        cv2.imwrite(output_path, cv2.cvtColor(blacked_out_image, cv2.COLOR_RGB2BGR))
        # OCR on blacked out image (sensitive text hidden)
        all_text += pytesseract.image_to_string(blacked_out_image)
    return all_text

# ========= 6. Main driver =========
if __name__ == "__main__":
    file_path = r"C:\Users\Sandhya\AI projects\pdf_deidentification\Employee Report sample.pdf"  # Change your input file path here
    output_folder = r"C:\Users\Sandhya\AI projects\pdf_deidentification\output"
    os.makedirs(output_folder, exist_ok=True)

    file_type = detect_file_type(file_path)

    if file_type == "image":
        output_path = os.path.join(output_folder, "blacked_out_output.png")
        text = process_image(file_path, output_path)
        print("Extracted Text:\n", text)
        print(f"Blacked out image saved to: {output_path}")

    elif file_type == "pdf":
        text = process_pdf(file_path, output_folder)
        print("Extracted Text:\n", text)
        print(f"Blacked out pages saved in: {output_folder}")

import os
from PIL import Image
import numpy as np
import cv2
import re
from pdf2image import convert_from_path
import pytesseract
import spacy
import easyocr


# ------------------- Tesseract Path (Windows) -------------------
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# ------------------- Load spaCy NER model -------------------
try:
    nlp = spacy.load("en_core_web_sm")
except:
    import spacy.cli
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

PII_VALUE_COLUMN_START_X = 300

# ------------------- Regex for PII Values -------------------
PII_VALUE_PATTERNS = [
    re.compile(r'\b\d{12}\b'),  # Aadhaar number
    re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),  # PAN number
    re.compile(r'\b\d{10}\b'),  # Mobile number
    re.compile(r'\b\d{5,6}\b'),  # PIN code or short ID
    re.compile(r'\b[A-Z]{2}\d{2}\s?[A-Z]{2}\d{4}\s?\d{4}\b', re.I),  # Vehicle number (new)
    re.compile(r'\b\d{2}[/-]\d{2}[/-]\d{4}\b'),  # Date of birth
    re.compile(r'\b[A-Z]{2}\d{7}\b', re.I),  # Passport number
    re.compile(r'\b\d{11,16}\b'),  # Bank account or card number
    re.compile(r'\b\d{9,}\b'),  # Generic long numeric IDs
    re.compile(r'\b[A-Z0-9]{10,15}\b', re.I),  # IFSC, UPI, alphanumeric IDs
    re.compile(r'\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}\b', re.I),  # GSTIN
    re.compile(r'\bMRN[-\s]?\d{3,10}\b', re.IGNORECASE),
    re.compile(
        r'\b(?:H\.?No\.?|Flat\s?No\.?|Door\s?No\.?|Plot\s?No\.?)?\s*\d+[A-Z\-]*[ ,]*[A-Za-z\s]*(Street|Road|Nagar|Puram|Layout|Colony|Avenue|Area|Block|Phase|Sector|Near|Opposite|PO|PIN|Tamil\s*Nadu|Karnataka|Kerala|Delhi|Mumbai|Chennai|Hyderabad|Pune|Bangalore)\b',
        re.IGNORECASE
    )
]
    
# ------------------- Face Detection -------------------
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

def detect_faces_cv(img_cv):
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, 1.1, 4)
    boxes = []
    for (x, y, w, h) in faces:
        padding = 10 
        boxes.append((x - padding, y - padding, x + w + padding, y + h + padding))
    return boxes

# ------------------- Signature detection placeholder -------------------
def detect_signatures_heuristic(img_cv):
    # Initialize EasyOCR reader
    reader = easyocr.Reader(['en'], gpu=False)

    # Convert to grayscale for better OCR
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    height = gray.shape[0]
    lower_half = gray[int(height / 2):, :]  # only bottom half (where signatures usually are)

    # Run OCR on the lower half
    results = reader.readtext(lower_half)

    boxes = []
    for (bbox, text, conf) in results:
        # bbox = [[x1,y1], [x2,y2], [x3,y3], [x4,y4]]
        # text = detected string
        # conf = confidence (0–1)

        # Adjust y-coordinates (since we cropped the lower half)
        adjusted_bbox = []
        for (x, y) in bbox:
            adjusted_bbox.append((x, y + int(height / 2)))

        # Calculate bounding rectangle
        x_coords = [pt[0] for pt in adjusted_bbox]
        y_coords = [pt[1] for pt in adjusted_bbox]
        x_min, x_max = min(x_coords), max(x_coords)
        y_min, y_max = min(y_coords), max(y_coords)

        w, h = x_max - x_min, y_max - y_min

        # Heuristic filtering — short words, low confidence text, etc.
        # Signatures are often single short words (like a name), or scribbles
        if len(text) <= 10 and conf < 0.8 and 200 < w * h < 60000:
            boxes.append((int(x_min), int(y_min), int(x_max), int(y_max)))

    return boxes


# ------------------- Text OCR -------------------
def detect_text_boxes_pytesseract(img_cv, conf_thresh=30):
    """
    Returns list of ((x1,y1,x2,y2), text) tuples for individual words/tokens.
    """
    rgb = cv2.cvtColor(img_cv, cv2.COLOR_BGR2RGB)
    data = pytesseract.image_to_data(
        rgb,
        config="--oem 3 --psm 6", 
        output_type=pytesseract.Output.DICT
    )
    
    word_boxes = []
    n_boxes = len(data['level'])
    for i in range(n_boxes):
        conf = int(data['conf'][i])
        text = data['text'][i].strip()
        if conf > conf_thresh and text: 
            x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
            word_boxes.append(((x, y, x + w, y + h), text))
    return word_boxes

def find_sensitive_text_boxes(word_data, image_width):
    redaction_boxes = []
    
    for (x1, y1, x2, y2), text in word_data:
        is_sensitive = False
        
        # 1. Check PII_VALUE_PATTERNS
        for pattern in PII_VALUE_PATTERNS:
            if pattern.search(text):
                is_sensitive = True
                break
        
        # 2. Check SpaCy NER for general PII (Name, Location, Date)
        if not is_sensitive:
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ in ["PERSON", "GPE", "DATE"]: 
                    is_sensitive = True
                    break

        if is_sensitive:
            # Apply the horizontal constraint to protect the labels
            padding = 5 
            
            # The redaction must start AT LEAST at the column boundary.
            redaction_x1 = max(x1 - padding, PII_VALUE_COLUMN_START_X) 
            
            redaction_y1 = y1 - padding
            redaction_x2 = x2 + padding
            redaction_y2 = y2 + padding
            
            # Only add a box if the redaction area is valid and not completely off-screen
            if redaction_x1 < redaction_x2:
                redaction_boxes.append((redaction_x1, redaction_y1, redaction_x2, redaction_y2))
            
    return redaction_boxes


# ------------------- Image Redaction -------------------
def process_image_full(path_or_image, redact_faces=True, redact_text=True, redact_signatures=True,
                       method="blackout", conf_threshold=30):
    """
    Redact only personal data (text values) and photos/signatures.
    """
    if isinstance(path_or_image, Image.Image):
        img_pil = path_or_image.convert("RGB")
    else:
        img_pil = Image.open(path_or_image).convert("RGB")

    img_cv = np.array(img_pil)[:, :, ::-1].copy()  # PIL -> OpenCV BGR
    
    all_redaction_boxes = []

    # ----------------- Faces -----------------
    if redact_faces:
        all_redaction_boxes.extend(detect_faces_cv(img_cv))

    # ----------------- Text -----------------
    if redact_text:
        text_data = detect_text_boxes_pytesseract(img_cv, conf_thresh=conf_threshold)
        all_redaction_boxes.extend(find_sensitive_text_boxes(text_data, img_cv.shape[1]))

    # ----------------- Signatures -----------------
    if redact_signatures:
        all_redaction_boxes.extend(detect_signatures_heuristic(img_cv))

    # ----------------- Apply Redaction -----------------
    for (x1, y1, x2, y2) in all_redaction_boxes:
        # Ensure coordinates are within image bounds
        x1, y1 = max(0, x1), max(0, y1)
        x2, y2 = min(img_cv.shape[1], x2), min(img_cv.shape[0], y2)
        
        if method == "blackout":
            img_cv[y1:y2, x1:x2] = 0
        else:
            if (y2 - y1 > 1) and (x2 - x1 > 1):
                roi = img_cv[y1:y2, x1:x2]
                kernel_size = 51 if (y2 - y1) > 50 else 21 
                img_cv[y1:y2, x1:x2] = cv2.GaussianBlur(roi, (kernel_size, kernel_size), 0)

    pil_out = Image.fromarray(img_cv[:, :, ::-1])
    return pil_out, "", all_redaction_boxes

# ------------------- PDF Redaction -------------------
def process_pdf_file(pdf_path, output_dir, method="blackout", conf_threshold=30, poppler_path=None):
    """
    Redact all pages of PDF.
    """
    if poppler_path is None:
        # UPDATE THIS TO YOUR ACTUAL POPPLER BIN PATH
        poppler_path = r"C:\Users\Sandhya\Downloads\Release-25.07.0-0\poppler-25.07.0\Library\bin"

    pages = convert_from_path(pdf_path, dpi=200, fmt='png', poppler_path=poppler_path)
    images = []
    page_summaries = []

    for i, page in enumerate(pages, start=1):
        pil_out, _, box_summary = process_image_full(
            page, method=method, conf_threshold=conf_threshold
        )
        images.append(pil_out)
        page_summaries.append(box_summary)

    return images, "", page_summaries

import streamlit as st
import tempfile
import os
from pathlib import Path
from main import detect_file_type, process_image, process_pdf  # adapt if needed

st.title("Sensitive Data Blackout - PDF & Image Deidentification")

uploaded_file = st.file_uploader("Upload PDF or Image", type=['pdf', 'png', 'jpg', 'jpeg'])

if uploaded_file:
    # Create a temp dir to save files
    with tempfile.TemporaryDirectory() as tmpdirname:
        input_path = os.path.join(tmpdirname, uploaded_file.name)
        with open(input_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        output_folder = os.path.join(tmpdirname, "output")
        os.makedirs(output_folder, exist_ok=True)

        file_type = detect_file_type(input_path)

        if file_type == "image":
            output_path = os.path.join(output_folder, "blacked_out_output.png")
            text = process_image(input_path, output_path)
            st.image(output_path, caption="Redacted Image", use_column_width=True)
            st.download_button("Download Redacted Image", open(output_path, "rb"), file_name="redacted.png")

        elif file_type == "pdf":
            text = process_pdf(input_path, output_folder)
            # Show all redacted pages as images
            pages = sorted(Path(output_folder).glob("page_*_blacked_out.png"))
            for i, page_path in enumerate(pages, 1):
                st.image(str(page_path), caption=f"Redacted Page {i}", use_column_width=True)
            # Bundle pages into zip for download
            import zipfile
            zip_path = os.path.join(tmpdirname, "redacted_pages.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                for page_path in pages:
                    zf.write(page_path, arcname=page_path.name)
            st.download_button("Download Redacted Pages (ZIP)", open(zip_path, "rb"), file_name="redacted_pages.zip")

        st.subheader("Extracted Text (from redacted content):")
        st.text_area("Text", value=text, height=200)

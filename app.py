import streamlit as st
import tempfile, os, zipfile, io
from main import process_pdf_file, process_image_full

st.title("Sensitive Data Blackout — Image & PDF De-identification")

# Options
method = st.radio("Redaction method", ["blackout", "blur"])

uploaded_file = st.file_uploader("Upload PDF or Image", type=['pdf','png','jpg','jpeg'])

if uploaded_file:
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, uploaded_file.name)
        with open(input_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        if uploaded_file.type == "application/pdf":
            st.info("Processing PDF pages...")
            images, _, page_summaries = process_pdf_file(input_path, tmpdir, method=method)

            # Display and bundle
            zip_path = os.path.join(tmpdir, "redacted_pages.zip")
            with zipfile.ZipFile(zip_path,"w") as zf:
                for i,img in enumerate(images,start=1):
                    buf = io.BytesIO()
                    img.save(buf,format="PNG")
                    zf.writestr(f"page_{i}_redacted.png", buf.getvalue())
                    st.image(img, caption=f"Page {i}", use_container_width=True)

            with open(zip_path,"rb") as f:
                st.download_button("Download Redacted Pages (ZIP)", data=f, file_name="redacted_pages.zip")

        else:
            pil_out, _, _ = process_image_full(input_path, method=method)
            st.image(pil_out, caption="Redacted Image", use_container_width=True)
            buf = io.BytesIO()
            pil_out.save(buf, format="PNG")
            st.download_button("Download Redacted Image", data=buf.getvalue(), file_name="redacted.png")

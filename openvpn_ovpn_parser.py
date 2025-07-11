import re
import tempfile
import os

def extract_embedded_blocks(ovpn_text):
    blocks = {"ca": None, "cert": None, "key": None}
    for tag in blocks.keys():
        pattern = rf"<{tag}>(.*?)</{tag}>"
        match = re.search(pattern, ovpn_text, re.DOTALL)
        if match:
            content = match.group(1).strip()
            temp_fd, temp_path = tempfile.mkstemp(suffix=f".{tag}.pem")
            with os.fdopen(temp_fd, 'w') as tmp:
                tmp.write(content)
            blocks[tag] = temp_path
        else:
            raise ValueError(f"Missing <{tag}> block in .ovpn file")
    return blocks

def load_ovpn_config(ovpn_file_path):
    with open(ovpn_file_path, 'r') as f:
        ovpn_text = f.read()
    return extract_embedded_blocks(ovpn_text)

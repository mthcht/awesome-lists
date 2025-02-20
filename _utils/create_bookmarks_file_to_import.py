#!/usr/bin/env python3
import re
from datetime import datetime

# URL to ignore
IGNORED_URL = "https://github.com/mthcht/awesome-lists/assets/75267080/059432aa-cfe9-46d1-a611-fbb225bce66e"

class BookmarkNode:
    def __init__(self, title="", url=None, is_folder=False):
        self.title = title.strip()
        self.url = url
        self.is_folder = is_folder
        self.children = []
        self.add_date = int(datetime.now().timestamp())

def parse_markdown(filepath):
    """
    Parse the markdown file into a tree of BookmarkNode objects.
    Handles headers (#) and list items (- or *).
    Ignores <details> tags and a specific unwanted URL.
    """
    root = BookmarkNode("Bookmarks", is_folder=True)
    # Stack holds tuples of (level, node); root is at level 0.
    stack = [(0, root)]
    
    header_re = re.compile(r"^(#{1,6})\s*(.+)$")
    link_re = re.compile(r"\[([^\]]+)\]\((https?://[^\)]+)\)")
    
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Skip <details> tags (only for visualization)
            if line.lower().startswith("<details") or line.lower().startswith("</details>"):
                continue

            # Process markdown headers
            header_match = header_re.match(line)
            if header_match:
                hashes, title = header_match.groups()
                # Rename specific folders
                if title.strip() == "Security lists for SOC/DFIR detections [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)":
                    title = "mthcht_lists"
                elif title.strip() == "My Detection Lists":
                    title = "Detection Lists"
                # Remove colon characters from folder names
                title = title.replace(":", "")
                level = len(hashes)
                while stack and stack[-1][0] >= level:
                    stack.pop()
                node = BookmarkNode(title, is_folder=True)
                stack[-1][1].children.append(node)
                stack.append((level, node))
                continue

            # Process list items starting with "-" or "*"
            if line.startswith("-") or line.startswith("*"):
                for match in link_re.finditer(line):
                    link_title, url = match.groups()
                    if url == IGNORED_URL:
                        continue
                    link_node = BookmarkNode(link_title, url=url, is_folder=False)
                    stack[-1][1].children.append(link_node)
                continue

            # Also capture inline markdown links in other lines
            for match in link_re.finditer(line):
                link_title, url = match.groups()
                if url == IGNORED_URL:
                    continue
                link_node = BookmarkNode(link_title, url=url, is_folder=False)
                stack[-1][1].children.append(link_node)
    
    return root

def generate_bookmarks_html(node, indent=0):
    """
    Recursively generate HTML lines for the bookmark nodes.
    """
    lines = []
    indent_str = "    " * indent
    if node.is_folder:
        if indent > 0:
            lines.append(f'{indent_str}<DT><H3 ADD_DATE="{node.add_date}" LAST_MODIFIED="{node.add_date}">{node.title}</H3>')
            lines.append(f'{indent_str}<DL><p>')
        for child in node.children:
            lines.extend(generate_bookmarks_html(child, indent + (1 if indent > 0 else 0)))
        if indent > 0:
            lines.append(f'{indent_str}</DL><p>')
    else:
        lines.append(f'{indent_str}<DT><A HREF="{node.url}" ADD_DATE="{node.add_date}">{node.title}</A>')
    return lines

def build_bookmarks_file(markdown_path, output_html_path):
    """
    Build the Netscape Bookmark file from the markdown input.
    """
    root = parse_markdown(markdown_path)
    html_lines = [
        "<!DOCTYPE NETSCAPE-Bookmark-file-1>",
        '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
        "<TITLE>Bookmarks</TITLE>",
        "<H1>Bookmarks</H1>",
        "<DL><p>"
    ]
    for child in root.children:
        html_lines.extend(generate_bookmarks_html(child, indent=1))
    html_lines.append("</DL><p>")
    
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_lines))
    
    print(f"✅ Bookmarks saved to: {output_html_path}")

if __name__ == "__main__":
    input_md = "../README.md"  
    output_html = "bookmarks.html"
    build_bookmarks_file(input_md, output_html)

#!/usr/bin/env python3
import re
import os
from datetime import datetime

# URL to ignore
IGNORED_URL = "https://github.com/mthcht/awesome-lists/assets/75267080/059432aa-cfe9-46d1-a611-fbb225bce66e"
# Base URL for the Lists folder on GitHub
LISTS_BASE_URL = "https://github.com/mthcht/awesome-lists/tree/main/Lists"
# Local folder containing the full detection lists structure
LISTS_FOLDER = "../Lists"

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
    Ignores <details> tags.
    Skips any header containing "my detection lists".
    """
    root = BookmarkNode("Bookmarks", is_folder=True)
    # Stack holds tuples of (level, node); root is at level 0.
    stack = [(0, root)]
    
    header_re = re.compile(r"^(#{1,6})\s*(.+)$")
    link_re = re.compile(r"\[([^\]]+)\]\((https?://[^\)]+)\)")
    
    skip_level = None  # When set, skip lines until a header with level <= skip_level
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Skip <details> tags (visualization only)
            if line.lower().startswith("<details") or line.lower().startswith("</details>"):
                continue

            # Check if line is a header
            header_match = header_re.match(line)
            if header_match:
                hashes, title = header_match.groups()
                level = len(hashes)
                # If we are skipping a section and this header is deeper, ignore it
                if skip_level is not None and level > skip_level:
                    continue
                # If header level is less or equal, end skipping
                if skip_level is not None and level <= skip_level:
                    skip_level = None
                # Skip any header containing "my detection lists"
                if "my detection lists" in title.strip().lower():
                    skip_level = level
                    continue

                # Rename specific headers and remove colons
                if title.strip() == "Security lists for SOC/DFIR detections [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)":
                    title = "mthcht_lists"
                title = title.replace(":", "")
                # Pop stack until correct level is reached
                while stack and stack[-1][0] >= level:
                    stack.pop()
                node = BookmarkNode(title, is_folder=True)
                stack[-1][1].children.append(node)
                stack.append((level, node))
                continue

            # Skip non-header lines if in a skipped section
            if skip_level is not None:
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

def parse_folder(path, base_url):
    """
    Recursively build a BookmarkNode tree from a directory.
    Each file gets a link constructed from the base_url.
    """
    folder_node = BookmarkNode(is_folder=True)
    for entry in sorted(os.scandir(path), key=lambda e: e.name.lower()):
        # Skip symbolic links explicitly
        if entry.is_symlink():
            continue
        if entry.is_dir():
            subfolder = parse_folder(entry.path, f"{base_url}/{entry.name}")
            subfolder.title = entry.name
            folder_node.children.append(subfolder)
        elif entry.is_file():
            file_node = BookmarkNode(entry.name, url=f"{base_url}/{entry.name}", is_folder=False)
            folder_node.children.append(file_node)
    return folder_node


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

def find_node_by_title(node, target_title):
    """
    Recursively find a node with the given title.
    """
    if node.title.lower() == target_title.lower():
        return node
    for child in node.children:
        result = find_node_by_title(child, target_title)
        if result:
            return result
    return None

def build_bookmarks_file(markdown_path, output_html_path):
    """
    Build the Netscape Bookmark file from the README markdown and inject the Lists folder.
    The detection lists folder is added inside the mthcht_lists node.
    """
    # Parse the README markdown
    root = parse_markdown(markdown_path)
    
    # Locate the mthcht_lists node in the parsed tree
    mthcht_node = find_node_by_title(root, "mthcht_lists")
    if mthcht_node and os.path.isdir(LISTS_FOLDER):
        lists_tree = parse_folder(LISTS_FOLDER, LISTS_BASE_URL)
        detection_node = BookmarkNode("detection lists", is_folder=True)
        detection_node.children = lists_tree.children
        mthcht_node.children.append(detection_node)
    
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
    input_md = "../README.md"  # Adjust as needed
    output_html = "bookmarks.html"
    build_bookmarks_file(input_md, output_html)

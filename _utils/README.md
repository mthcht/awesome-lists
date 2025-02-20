# Bookmark Generator

After each update of the main README.md, this Python script is automatically executed, it parses my main markdown file `README.md` and produces a valid Netscape‐style Bookmark HTML file. It can optionally ignore certain URLs or sections and also inject additional folders from a local directory.  

## Features

- **Markdown Parsing**: Scans headers and links from my `README.md`, forming a hierarchical folder and link structure.  
- **Section Skipping**: Ignores user‐defined headers like "My Detection Lists" and excludes any specified URLs (replaced by the Folder Injection) 
- **Folder Injection**: Reads the local directory `../Lists` and inserts that structure (with GitHub URLs) into a bookmark folder  
- **Clean HTML**: Outputs a fully valid Netscape‐style Bookmark file, ready for import into your browser.

## Bookmark Usage
Download the `bookmarks.html` and import the bookmark in your browser:

#### Chrome
- At the top right "tree dot" setting, navigate to "Bookmarks and lists" and then "Import bookmarks and settings".
- Select Choose file.
- Choose the `bookmarks.html` and select "Open" and then "Done".

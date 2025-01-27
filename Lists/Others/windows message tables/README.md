extraction usage example:

```powershell
Add-Type -Path "C:\Users\mthcht\messagetablereader\messagetablereader.dll"
$messageTable = New-Object MessageTableReader.Reader
$messageTable.GetMessageList()
```

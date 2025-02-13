rule BrowserModifier_Win32_iLookup_143574_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/iLookup"
        threat_id = "143574"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "iLookup"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".com/toolbar/bar/" ascii //weight: 1
        $x_1_2 = {69 6e 65 62 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = "BroadcastSystemMessage" ascii //weight: 1
        $x_1_4 = "popup_enabled" ascii //weight: 1
        $x_1_5 = "%s%s&vid=%lu&ccod=%lu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_iLookup_143574_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/iLookup"
        threat_id = "143574"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "iLookup"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Search the web" wide //weight: 1
        $x_1_2 = "; dialoghide: 0; edge: sunken; help: 0; resizable: 0; scroll: 1; status: 0; unadorned: 0;" ascii //weight: 1
        $x_1_3 = {69 6e 65 62 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


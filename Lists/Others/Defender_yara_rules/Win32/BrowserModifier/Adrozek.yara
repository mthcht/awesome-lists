rule BrowserModifier_Win32_Adrozek_282179_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Adrozek"
        threat_id = "282179"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Adrozek"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 d2 75 33 80 39 4c 75 2e 80 79 01 6f 75 28 80 fb 78 75 23 80 79 0d 41 75 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Adrozek_282179_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Adrozek"
        threat_id = "282179"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Adrozek"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Adrozek_282179_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Adrozek"
        threat_id = "282179"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Adrozek"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 2e 00 61 00 76 00 61 00 73 00 74 00 63 00 6f 00 6e 00 66 00 69 00 67 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Adrozek_282179_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Adrozek"
        threat_id = "282179"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Adrozek"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "105B80DE-95F1-11D0-B0A0-00AA00BDCB5C" ascii //weight: 1
        $x_1_2 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 43 00 4c 00 53 00 49 00 44 00 5c 00 7b 00 34 00 37 00 32 00 30 00 38 00 33 00 42 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Adrozek_282179_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Adrozek"
        threat_id = "282179"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Adrozek"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Folder\\ShellEx\\ContextMenuHandlers\\avast" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


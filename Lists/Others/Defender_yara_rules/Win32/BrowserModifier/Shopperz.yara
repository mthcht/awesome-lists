rule BrowserModifier_Win32_Shopperz_223248_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Shopperz"
        threat_id = "223248"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Shopperz"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Approved Extensions" wide //weight: 1
        $x_1_2 = "SOFTWARE\\V-bates" wide //weight: 1
        $x_1_3 = "21EAF666-26B3-4a3c-ABD0-CA2F5A326744" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Shopperz_223248_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Shopperz"
        threat_id = "223248"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Shopperz"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 00 70 00 c7 45 ?? 70 00 72 00 c7 45 ?? 6f 00 76 00 c7 45 ?? 65 00 64 00 c7 45 ?? 20 00 45 00 c7 45 ?? 78 00 74 00 c7 45 ?? 65 00 6e 00 c7 45 ?? 73 00 69 00 c7 45 ?? 6f 00 6e 00 c7 45 ?? 73 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff 5c 00 49 00 c7 85 ?? ?? ff ff 6e 00 74 00 c7 85 ?? ?? ff ff 65 00 72 00 c7 85 ?? ?? ff ff 6e 00 65 00 c7 85 ?? ?? ff ff 74 00 20 00 c7 85 ?? ?? ff ff 45 00 78 00 c7 85 ?? ?? ff ff 70 00 6c 00 c7 85 ?? ?? ff ff 6f 00 72 00 c7 85 ?? ?? ff ff 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\shopperz" wide //weight: 1
        $x_1_4 = "5081D2D4-1637-404c-B74F-50526718257D" wide //weight: 1
        $x_1_5 = {43 3a 5c 77 6f 72 6b 5c 73 68 6f 70 70 65 72 7a [0-64] 49 6e 50 72 6f 67 72 65 73 73 5c 43 6f 6d 70 6f 6e 65 6e 74 73 5c 42 69 6e 61 72 69 65 73 5c 52 65 6c 65 61 73 65 5c 45 78 74 65 6e 73 69 6f 6e 02 00 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


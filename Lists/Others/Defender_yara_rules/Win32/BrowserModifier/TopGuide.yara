rule BrowserModifier_Win32_TopGuide_195947_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/TopGuide"
        threat_id = "195947"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "TopGuide"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 6f 70 47 75 69 64 65 2e 69 6e 69 00 00 00 00 68 74 74 70 3a 2f 2f 74 6f 70 67 75 69 64 65 2e 63 6f 2e 6b 72 2f 75 70 64 61 74 65 2f}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\TopGuide" ascii //weight: 1
        $x_1_3 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b 00 61 64 63 2e 64 6c 6c 00 49 6e 66 6f 54 61 62 00 54 6f 70 47 75 69 64 65 5f}  //weight: 1, accuracy: High
        $x_1_4 = {54 6f 70 47 75 69 64 65 2e 64 6c 6c 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_TopGuide_195947_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/TopGuide"
        threat_id = "195947"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "TopGuide"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 6f 66 74 77 61 72 65 5c 53 6d 61 72 74 54 6f 6f 6c 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 6d 61 72 74 54 6f 6f 6c 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_1_3 = {2e 70 6c 75 73 74 61 62 2e 63 6f 2e 6b 72 2f 75 70 64 61 74 65 2f 00}  //weight: 1, accuracy: High
        $x_1_4 = "shop.com/search/" ascii //weight: 1
        $x_1_5 = "/topguide.co.kr/bar.asp?k=%s&id=%s&m=%s" ascii //weight: 1
        $x_1_6 = {53 45 41 52 43 48 5f 4b 45 59 57 4f 52 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


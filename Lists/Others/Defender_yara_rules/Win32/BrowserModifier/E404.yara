rule BrowserModifier_Win32_E404_18087_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/E404"
        threat_id = "18087"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "E404"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: High
        $x_10_2 = "ObtainUserAgentString" ascii //weight: 10
        $x_10_3 = {6c 69 76 65 2e 00 00 00 6d 73 6e 2e 00 00 00 00 72 64 73 2e 79 61 68 6f 6f 2e 00 00 79 61 68 6f 6f 2e 00 00 67 6f 6f 67 6c 65 2e}  //weight: 10, accuracy: High
        $x_10_4 = {3f 70 3d 00 26 70 3d 00 3f 71 3d 00 26 71 3d}  //weight: 10, accuracy: High
        $x_10_5 = {18 92 d0 f7 d7 46 3d 4d 9b 7f 31 52 04 cd 08 36}  //weight: 10, accuracy: High
        $x_1_6 = "E404.e404mgr" ascii //weight: 1
        $x_1_7 = {c6 45 d0 75 c6 45 d1 72 c6 45 d2 6c c6 45 da 63 c6 45 db 6c c6 45 dc 69 c6 45 dd 63 c6 45 de 6b c6 45 df 73 c6 45 e4 72 c6 45 e5 65 c6 45 e6 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_E404_18087_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/E404"
        threat_id = "18087"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "E404"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "e404mgr ClassW" ascii //weight: 1
        $x_1_2 = {65 34 30 34 6d 67 72 57 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 65 34 30 34 6d 67 72}  //weight: 1, accuracy: Low
        $x_1_3 = "E404LibW" ascii //weight: 1
        $x_1_4 = "e404 1.0 Type LibraryW" ascii //weight: 1
        $x_1_5 = "e404.DLL" ascii //weight: 1
        $x_1_6 = "e404 Module" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule PWS_Win32_Dexter_A_2147683003_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dexter.A"
        threat_id = "2147683003"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 70 64 61 74 65 4d 75 74 65 78 3a 00 [0-3] 72 65 73 70 6f 6e 73 65 3d 00 00 [0-3] 70 61 67 65 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {44 65 74 65 63 74 53 68 75 74 64 6f 77 6e 43 6c 61 73 73 00 64 6f 77 6e 6c 6f 61 64 2d 00 00 [0-3] 75 70 64 61 74 65 2d 00 63 68 65 63 6b 69 6e 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dexter_2147683822_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dexter!dll"
        threat_id = "2147683822"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexter"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\HelperSolutions Software" wide //weight: 1
        $x_1_2 = {83 f9 72 75 25 c6 85 ?? ?? ?? ?? 5b c6 85 ?? ?? ?? ?? 63 c6 85 ?? ?? ?? ?? 5d c6 85 ?? ?? ?? ?? 00 c7 45 ?? 03 00 00 00 eb 12}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 0c 0f be 08 33 d1 8b 45 08 88 10 8b 4d 0c 83 c1 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule BrowserModifier_Win32_Kronaldaler_227496_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Kronaldaler"
        threat_id = "227496"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Kronaldaler"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 6f 6e 4f 76 65 72 6c 61 79 45 78 2e 64 6c 6c 00 44 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {2e 00 76 00 63 00 2f 00 3f}  //weight: 1, accuracy: High
        $x_1_3 = "Shell Overlay Shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


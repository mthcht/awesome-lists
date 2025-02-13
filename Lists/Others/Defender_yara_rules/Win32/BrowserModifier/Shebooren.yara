rule BrowserModifier_Win32_Shebooren_156009_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Shebooren"
        threat_id = "156009"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Shebooren"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 65 42 72 6f 77 73 65 72 43 6d 70 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 66 42 72 6f 77 73 65 72 43 6d 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_5_3 = {55 00 72 00 6c 00 52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 2e 00 63 00 70 00 70 00 00 00}  //weight: 5, accuracy: High
        $x_5_4 = {32 c3 24 0f 32 c3 6a 01 8d 4c 24 ?? 04 ?? 51 8d 4c 24 ?? 88 44 24 ?? e8 ?? ?? ?? ?? 8a 06 84 c0 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule BrowserModifier_Win32_EyeOnIE_A_166901_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/EyeOnIE.A"
        threat_id = "166901"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "EyeOnIE"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 68 6f 50 6c 75 67 69 6e 2e 45 79 65 4f 6e 49 45 2e 31 0a 00 48 4b 43 52 0d 0a 7b 0d 0a 09}  //weight: 1, accuracy: Low
        $x_1_2 = "{6E28339B-7A2A-47B6-AEB2-46BA53782379}" ascii //weight: 1
        $x_1_3 = {77 77 77 00 77 77 00 00 77 00 00 00 77 77 77 2e 00 00 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


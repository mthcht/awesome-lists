rule BrowserModifier_Win32_Satrap_226359_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Satrap!bit"
        threat_id = "226359"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Satrap"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 24 18 8b 4c 24 24 c0 e3 04 0a c3 83 c4 08 c0 ea 04 88 45 00 45 32 d0 41 3b f7 88 54 24 10 89 4c 24 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


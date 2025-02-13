rule BrowserModifier_Win32_MalPro_223390_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/MalPro"
        threat_id = "223390"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "MalPro"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\MalwareProtection360Installed" wide //weight: 1
        $x_1_2 = "MalwareProtection360.Properties" ascii //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 31 00 68 00 78 00 74 00 6c 00 39 00 7a 00 6e 00 71 00 77 00 65 00 6a 00 6a 00 2e 00 63 00 6c 00 6f 00 75 00 64 00 [0-15] 2e 00 6e 00 65 00 74 00 2f 00 61 00 70 00 69 00 2f 00 69 00 6d 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


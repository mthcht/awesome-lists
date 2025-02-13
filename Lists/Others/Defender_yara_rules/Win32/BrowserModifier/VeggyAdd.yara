rule BrowserModifier_Win32_VeggyAdd_223511_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/VeggyAdd"
        threat_id = "223511"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "VeggyAdd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\extensions\\staged\\" wide //weight: 1
        $x_1_2 = {65 78 74 65 6e 64 5f 04 00 2e 65 78 65 00 [0-15] 00 65 3d 64 6f 77 6e 6c 6f 61 64 65 6e 64 26 73 3d [0-9] 26 69 3d [0-9] 26 76 3d 04 00 2e 04 00 2e 04 00 2e 04 00 26 65 63 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule BrowserModifier_Win32_Yisou_141957_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Yisou"
        threat_id = "141957"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Yisou"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 45 46 31 44 31 37 41 39 2d 30 38 39 46 2d 34 30 63 63 2d 38 44 36 34 2d 37 33 32 34 43 44 45 42 41 30 44 42 7d 00 00 59 69 53 6f 75 00 00 00 44 72 61 67 53 65 61 72 63 68}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\3721\\yisou" ascii //weight: 1
        $x_1_3 = "client_bar_sdrag&p=%s" ascii //weight: 1
        $x_1_4 = {42 68 6f 4f 62 6a 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


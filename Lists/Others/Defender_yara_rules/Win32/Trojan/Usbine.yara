rule Trojan_Win32_Usbine_B_2147600153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Usbine.B"
        threat_id = "2147600153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Usbine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 6f 61 64 00 2e 65 78 65 00 22 25 31 22 20 25 2a 00 5c 3f 3f 5c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 5c 57 69 6e 6c 6f 67 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {80 38 2c 75 03 c6 00 00 68 00 01 00 00 68 ?? ?? 41 00 e8 ?? ?? ff ff 68 00 01 00 00 68 ?? ?? 41 00 e8 ?? ?? 00 00 c6 80 ?? ?? 41 00 5c c7 80 ?? ?? 41 00 55 73 65 72 c7 80 ?? ?? 41 00 69 6e 69 74 c7 80 ?? ?? 41 00 2e 65 78 65 68 ?? ?? 41 00 68 ?? ?? 41 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


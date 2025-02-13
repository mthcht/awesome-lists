rule Trojan_Win32_Rarnmel_A_2147626959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rarnmel.A"
        threat_id = "2147626959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rarnmel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 68 d4 fe ff ff 56 ff 15 ?? ?? 00 10 b9 4a 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 2c 01 00 00 50 56 c7 44 24 1c 00 00 00 00 ff 15 ?? ?? 00 10 56 ff 15 ?? ?? 00 10 8d 4c 24 10}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 01 74 0d 68 c8 00 00 00 ff d7 46 83 fe 14 7c e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


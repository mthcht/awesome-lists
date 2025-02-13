rule Trojan_Win32_Ikytoky_A_2147647990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ikytoky.A"
        threat_id = "2147647990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ikytoky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 20 8d 4d d0 51 68 6b 6b 00 00 68 6b 6b 00 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 f4 01 00 00 8b 8d 60 fe ff ff 51 8b 95 50 fe ff ff 52 6a 00 0f b7 45 14 50 8d 8d 48 fa ff ff 51 8b 95 64 fe ff ff 52 8b 85 4c fe ff ff 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


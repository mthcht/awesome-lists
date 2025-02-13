rule Trojan_Win32_Windam_A_2147659148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windam.A"
        threat_id = "2147659148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 36 61 66 63 34 33 38 36 38 66 6c 6b 67 64 62 64 34 30 66 62 66 36 64 35 65 64 35 30 39 30 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 2f 75 00 00 8d 8d ?? ?? ff ff 6a 00 c7 45 fc 01 00 00 00 51 c6 85 ?? ?? ff ff 00 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f8 85 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


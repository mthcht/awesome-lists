rule Trojan_Win32_Winzlock_A_2147647281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winzlock.A"
        threat_id = "2147647281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winzlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 34 ff ff ff 8b 48 04 8b 55 f0 89 51 08 8b 45 f0 89 45 ec 8b 4d ec 8b 51 04}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 08 8b 4d 08 03 4d f8 88 01 8b 55 f8 3b 55 0c 73 ?? 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ec 3c 8b 45 0c 03 45 08 2b 45 0c 89 45 fc 8d 4d fc 51 b9}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 fc 8b 4d fc 89 8d d4 fd ff ff 8d 95 18 fd ff ff 89 55 f8 b8 01 00 00 00 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


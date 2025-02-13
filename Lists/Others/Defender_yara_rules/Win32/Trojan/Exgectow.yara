rule Trojan_Win32_Exgectow_A_2147711520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Exgectow.A"
        threat_id = "2147711520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Exgectow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 e8 ?? ?? ff ff 89 45 fc 83 7d fc 00 74 0e ff 75 10 ff 75 0c ff 75 08 ff 55 fc eb 03 6a 01 58 c9 c2 0c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 [0-8] 2b c3 [0-8] 89 45 [0-8] 9d [0-8] 61 [0-8] 8b 45 [0-8] 8b 00 8b 00 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {2d d2 13 40 00 8b 4d [0-8] 2b c8 [0-8] 89 4d [0-8] 8d [0-8] 50 6a 40 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


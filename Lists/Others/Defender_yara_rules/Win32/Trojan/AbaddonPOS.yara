rule Trojan_Win32_AbaddonPOS_A_2147707606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AbaddonPOS.A"
        threat_id = "2147707606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AbaddonPOS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 39 30 72 ?? 80 39 39 [0-15] 80 39 5e [0-4] 80 39 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {31 0b 81 3b 55 89 e5 8b 74 0e 83 f8 00 75 09 31 0b 29 c3 31 c0 41}  //weight: 1, accuracy: High
        $x_1_3 = {81 be a0 01 00 00 00 f4 01 00 74 24 81 be a0 01 00 00 00 e8 03 00 74 18 81 be a0 01 00 00 00 dc 05 00 74 0c 81 be a0 01 00 00 00 d6 06 00 75 08 6a 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


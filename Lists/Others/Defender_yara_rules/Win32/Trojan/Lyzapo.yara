rule Trojan_Win32_Lyzapo_A_2147626614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lyzapo.A"
        threat_id = "2147626614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lyzapo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 20 bf 02 00 f3 ab d9 ee dd 5d d8 d9 ee dd 5d d0 66 ab aa}  //weight: 1, accuracy: High
        $x_1_2 = {83 c0 1e 50 ff 15 ?? ?? ?? 10 ff 75 fc ff 15 ?? ?? ?? 10 ff 45 f8 83 45 0c 04 8b 45 f8 3b 86 ?? ?? 00 00 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = {59 59 8b 75 0c c1 ee 0a 83 e6 01 e8 ?? ?? ?? 00 6a 05 99 59 f7 f9}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 45 e8 39 5d e4 74 0e 8b 45 e8 6a 06 99 59 f7 f9 83 fa 01 75 2d}  //weight: 1, accuracy: High
        $x_1_5 = {8d 4d d8 6a 08 51 50 89 5d fc ff d6 8d 45 fc 53 50 8d 45 f8 6a 04 50 ff 75 f0 ff d6 83 7d fc 04 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


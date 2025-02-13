rule Trojan_Win32_Alvabrig_A_2147623562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alvabrig.A"
        threat_id = "2147623562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alvabrig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7a 03 64 6f 77 73 75 3f 8b 45 0c 25 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 40 04 91 c1 e9 02 81 30 ?? ?? ?? ?? c1 00 02 83 c0 04 e2 f2}  //weight: 1, accuracy: Low
        $x_1_3 = {b0 e8 f2 ae 0b c9 74 ?? 8b c2 2b c7 39 07 75 f0}  //weight: 1, accuracy: Low
        $x_2_4 = {01 4d 20 01 4d 50 01 8d a4 00 00 00 05 00 b9}  //weight: 2, accuracy: Low
        $x_1_5 = {c1 e9 02 39 18 74 11 81 38 ?? ?? ?? ?? 74 09 81 30 ?? ?? ?? ?? c1 00 02 83 c0 04 [0-2] e2}  //weight: 1, accuracy: Low
        $x_1_6 = {b0 68 ba 6f 73 74 73 be 6f 73 6d 73 8b 7d fc 83 e9}  //weight: 1, accuracy: High
        $x_1_7 = {4a 8a 07 32 c1 03 c9 fe c1 aa 4a 75 f4 8b 3d ?? ?? ?? ?? 8b cf b0 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


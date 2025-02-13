rule Trojan_Win64_Shaolaod_A_2147928136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shaolaod.A"
        threat_id = "2147928136"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shaolaod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 5e c0 84 c7 [0-6] 02 9f e6 6a c7 [0-6] f4 15 93 b0 c7}  //weight: 2, accuracy: Low
        $x_2_2 = {ff 1f 7c c9 c7 [0-6] 6c e1 eb 9f c7 [0-6] 35 f6 53 22 c7}  //weight: 2, accuracy: Low
        $x_1_3 = {b8 01 00 00 00 48 6b c0 01 c6 [0-7] b8 01 00 00 00 48 6b c0 02 c6 [0-7] b8 01 00 00 00 48 6b c0 03 c6}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 01 00 00 00 c1 e2 00 c6 ?? ?? ?? ?? b8 01 00 00 00 d1 e0 c6 ?? ?? ?? ?? b9 01 00 00 00 6b d1 03 c6}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 45 f4 de ce be ae c7 45 d0 de ce be da c7 45 e8 dd cc bb aa c7 45 ec db ce ee aa c7 45 e4 dd cc aa bb c7 45 e0 dd cc bb cc}  //weight: 1, accuracy: High
        $x_1_6 = {25 00 00 00 66 [0-5] 75 00 00 00 66 [0-5] 73 00 00 00 66 [0-5] 65 00 00 00 66 [0-5] 72 00 00 00 66}  //weight: 1, accuracy: Low
        $x_1_7 = {b8 6d 00 00 00 66 [0-7] b8 73 00 00 00 66 [0-7] b8 76 00 00 00 66 [0-7] b8 63 00 00 00 66 [0-7] b8 72 00 00 00 66 [0-7] b8 74 00 00 00 66 [0-7] b8 2e 00 00 00 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


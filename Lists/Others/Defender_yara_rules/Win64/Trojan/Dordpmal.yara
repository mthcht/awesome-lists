rule Trojan_Win64_Dordpmal_A_2147938582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dordpmal.A"
        threat_id = "2147938582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dordpmal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 8b c8 b8 1f 85 eb 51 41 f7 e9 b8 93 24 49 92 c1 fa 05 44 8b c2 41 c1 e8 1f 41 03 d0 6b d2 64}  //weight: 2, accuracy: High
        $x_1_2 = {48 8b ce 48 83 c9 0f 48 3b cf 77 44 48 8b d5 48 8b c7 48 d1 ea 48 2b c2 48 3b e8 77 33 48 8d 04 2a}  //weight: 1, accuracy: High
        $x_1_3 = "libksjgog2.dll" ascii //weight: 1
        $x_1_4 = "adasdasasdasasd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


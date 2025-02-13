rule Trojan_Win64_SharpWipe_A_2147847602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SharpWipe.A!dha"
        threat_id = "2147847602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SharpWipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 d4 43 00 3a 00 c7 45 d8 5c 00 57 00 c7 45 dc 69 00 6e 00 c7 45 e0 64 00 6f 00 c7 45 e4 77 00 73 00 c7 45 e8 5c 00 69 00 c7 45 ec 6d 00 67 00 c7 45 f0 2e 00 69 00 c7 45 f4 73 00 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 98 25 00 73 00 c7 45 9c 20 00 2d 00 c7 45 a0 61 00 63 00 c7 45 a4 63 00 65 00 c7 45 a8 70 00 74 00 c7 45 ac 65 00 75 00 c7 45 b0 6c 00 61 00 c7 45 b4 20 00 2d 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 b8 72 00 20 00 c7 45 bc 2d 00 73 00 c7 45 c0 20 00 2d 00 c7 45 c4 71 00 20 00 c7 45 c8 25 00 63 00 c7 45 cc 3a 00 5c 00 c7 45 d0 2a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


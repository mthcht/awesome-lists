rule Trojan_Win64_LunarRobin_A_2147980986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LunarRobin.A"
        threat_id = "2147980986"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LunarRobin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 56 41 54 41 55 41 56 41 57 48 83 ec 08 48 89 e5 48 83 fa 01 74 1b 48}  //weight: 1, accuracy: High
        $x_1_2 = {48 31 c0 48 31 c9 48 31 d2 b8 01 00 00 00 53 0f a2 5b 0f ba e1 1e 73 06 48 0f c7 f0 eb 05 0f ae e8 0f 31}  //weight: 1, accuracy: High
        $x_1_3 = {48 83 e8 02 48 25 ff 00 00 00 65 4c 8b 18 48 c7 c0 15 00 00 00 48 83 c0 03 49 8b 1c 03 48 c7 c0 1f 00 00 00 48 83 c0 01 48 8b 1c 03}  //weight: 1, accuracy: High
        $x_2_4 = {48 83 f7 00 5f 48 8d 3f 41 56 49 c1 ce 40 4d 31 f6 49 83 e6 ff 49 ff c6}  //weight: 2, accuracy: High
        $x_2_5 = {58 48 89 f6 56 48 c1 c6 00 48 8d 34 24 48 8d 36 48 83 c6 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


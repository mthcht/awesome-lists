rule Trojan_Win64_PrintSpoofer_LR_2147978899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrintSpoofer.LR!MTB"
        threat_id = "2147978899"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrintSpoofer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {b8 1f 85 eb 51 4c 8b c9 41 f7 e0 48 83 e9 02 c1 ea 05 6b c2 64 44 2b c0 41 8b c0 44 8b c2 48 8d 15 87 4e 02 00 0f b7 04 42 66 89 01 41 83 f8 0a}  //weight: 20, accuracy: High
        $x_1_2 = "[TokenSteal] found PID=%lu IL=%s" ascii //weight: 1
        $x_2_3 = "[TokenSteal] after SetThreadToken IL=%s" ascii //weight: 2
        $x_3_4 = "High via TokenSteal:" ascii //weight: 3
        $x_4_5 = "duplicating" ascii //weight: 4
        $x_5_6 = "Token stolen from PID" ascii //weight: 5
        $x_6_7 = "CreateProcessWithTokenW winlogon pid=" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_20_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_20_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}


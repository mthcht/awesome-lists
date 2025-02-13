rule VirTool_Win64_SyKiller_A_2147905430_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SyKiller.A"
        threat_id = "2147905430"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SyKiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 85 50 79 00 00 ff ?? ?? ?? ?? ?? 48 89 c6 b9 20 00 00 00 ba 10 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 f1 89 c2 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 a0 79 00 00 89 95 a4 79 00 00 e8 ?? ?? ?? ?? 48 89 c6 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 f1 48 89 c2 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 85 60 79 00 00 01 00 00 00 48 8b 85 a0 79 00 00 48 89 85 64 79 00 00 c7 85 6c 79 00 00 02 00 00 00 48 8b b5 50 79 00 00 31 c9 e8 ?? ?? ?? ?? 66 0f ef c0 f3 0f 7f 44 24 20 ?? ?? ?? ?? ?? ?? ?? 48 89 f1 41 b9 10 00 00 00 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = "S4Killer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


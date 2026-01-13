rule VirTool_Win64_Credesz_A_2147958318_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Credesz.A"
        threat_id = "2147958318"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Credesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b c3 49 8b d6 e8 [0-17] 48 39 44 24 60 [0-16] c7 44 24 68 01 00 00 00 41 b9 04 00 00 00 48 89 44 24 20 ?? ?? ?? ?? ?? 48 8b d6 48 8b cf ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 41 b9 04 00 00 00 89 5d ?? ?? ?? ?? ?? 48 89 44 24 20 49 8b d6 48 8b cf ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 83 7d a0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Credesz_A_2147958318_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Credesz.A"
        threat_id = "2147958318"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Credesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 45 31 e4 45 31 ed 45 31 f6 4c 8b 84 24 28 01 00 00 48 8b 94 24 30 01 00 00 [0-22] e8 ?? ?? ?? ?? 31 d2 31 c9 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 f1 48 89 84 24 50 03 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 84 24 e0 04 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 bc 24 d8 04 00 00 4c 89 84 24 a8 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? c7 84 24 d0 04 00 00 01 00 00 00 48 89 84 24 a0 02 00 00 ff ?? ?? ?? ?? ?? 48 89 f1 89 c7 ?? ?? ?? 48 89 d9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


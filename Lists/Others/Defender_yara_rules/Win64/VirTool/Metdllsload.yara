rule VirTool_Win64_Metdllsload_A_2147931741_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Metdllsload.A"
        threat_id = "2147931741"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Metdllsload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c2 83 e0 07 42 0f b6 04 00 30 04 11 48 ff c2 48 3b d7}  //weight: 1, accuracy: High
        $x_1_2 = {48 c7 44 24 28 00 00 00 00 89 44 24 20 45 33 c9 33 d2 48 c7 c1 ff ff ff ff 41 b8 40 00 00 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Metdllsload_B_2147939550_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Metdllsload.B"
        threat_id = "2147939550"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Metdllsload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0d d1 ?? 00 00 48 8b ?? 83 e0 07 [0-16] 30 04 ?? 48 ff ?? 48 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 28 00 00 00 00 89 44 24 20 45 33 c9 33 d2 48 c7 c1 ff ff ff ff 41 b8 40 00 00 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


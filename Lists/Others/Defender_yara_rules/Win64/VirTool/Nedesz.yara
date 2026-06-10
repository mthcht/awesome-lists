rule VirTool_Win64_Nedesz_A_2147971339_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nedesz.A"
        threat_id = "2147971339"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 30 4c 8b ce 4c 89 74 24 20 ff ?? ?? ?? ?? ?? 8b f8 85 c0 ?? ?? b9 02 00 00 00 ff ?? ?? ?? ?? ?? 41 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 30 ?? ?? ?? ?? 41 b9 20 00 00 00 48 89 44 24 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8b f8 85 c0 ?? ?? b9 02 00 00 00 ff ?? ?? ?? ?? ?? 41 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


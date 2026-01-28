rule VirTool_Win64_Redebesz_A_2147961813_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Redebesz.A"
        threat_id = "2147961813"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Redebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 08 57 48 83 ec 20 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b c8 ?? ?? ?? ?? ?? ?? ?? 48 8b f8 ff ?? ?? ?? ?? ?? 48 8b d7}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d8 e8 ?? ?? ?? ?? 48 8b d3 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 5c 24 30 33 c0 48 83 c4 20 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


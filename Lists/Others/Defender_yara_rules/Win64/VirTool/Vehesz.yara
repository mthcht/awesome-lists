rule VirTool_Win64_Vehesz_A_2147971340_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vehesz.A"
        threat_id = "2147971340"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vehesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b cb 48 8b 45 c0 48 89 ?? ?? ?? ?? ?? 48 8b 45 c8 48 89 ?? ?? ?? ?? ?? 48 8b 45 d0 48 89 ?? ?? ?? ?? ?? 48 8b 45 d8 48 89}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f8 48 85 db ?? ?? 44 8b c0 ?? ?? ?? ?? ?? ?? ?? 48 8b d3 e8 ?? ?? ?? ?? 85 ff ?? ?? 8b d7 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


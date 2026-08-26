rule VirTool_Win64_Deresz_A_2147977019_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Deresz.A"
        threat_id = "2147977019"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Deresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 38 ?? ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 48 c7 c1 ff ff ff ff 48 89 ?? ?? ?? ?? ?? 48 c7 44 24 40 00 10 00 00 48 c7 44 24 48 00 10 00 00 c7 44 24 20 00 30 00 00 e8 ?? ?? ?? ?? 85 c0 ?? ?? 8b d0}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 28 40 00 00 00 45 33 c0 c7 44 24 20 00 30 00 00 ?? ?? ?? ?? ?? 48 c7 c1 ff ff ff ff e8 ?? ?? ?? ?? 85 c0 ?? ?? 8b d0 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Skenesz_A_2147965079_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Skenesz.A"
        threat_id = "2147965079"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Skenesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 81 ec ?? ?? 00 00 48 89 84 24 f0 03 00 00 4c 89 8c 24 20 04 00 00 48 89 bc 24 08 04 00 00 48 89 8c 24 00 04 00 00 ?? ?? ?? 48 83 fb 04 ?? ?? ?? ?? ?? ?? 48 83 fb 05 ?? ?? ?? ?? ?? ?? 81 38 ?? ?? ?? ?? ?? ?? 80 78 04 ?? ?? ?? 4c 89 c0 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 5a 10 48 8b 54 24 28 48 8b 42 10 48 8b 4a 18 e8 ?? ?? ?? ?? ?? ?? 31 c0 48 83 c4 18 5d c3 48 89 44 24 08 48 89 5c 24 10 e8 ?? ?? ?? ?? 48 8b 44 24 08 48 8b 5c 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


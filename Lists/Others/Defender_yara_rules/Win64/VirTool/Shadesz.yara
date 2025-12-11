rule VirTool_Win64_Shadesz_A_2147959256_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shadesz.A"
        threat_id = "2147959256"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shadesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 3b 66 10 ?? ?? 55 48 89 e5 48 83 ec 08 48 8b ?? ?? ?? ?? ?? 48 85 c9 ?? ?? 48 8b ?? ?? ?? ?? ?? 48 83 c4 08 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 81 ec a0 00 00 00 48 89 8c 24 c0 00 00 00 48 89 b4 24 d0 00 00 00 48 89 84 24 b0 00 00 00 48 89 5c 24 68 48 89 4c 24 70 48 89 7c 24 78 48 89 b4 24 80 00 00 00 4c 89 84 24 88 00 00 00 [0-21] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


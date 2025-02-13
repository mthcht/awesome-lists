rule VirTool_Win64_Rusol_A_2147930829_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rusol.A"
        threat_id = "2147930829"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rusol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 50 e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 84 24 c0 00 00 00 b8 08 00 00 00 48 89 84 24 c8 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 8c 24 d0 00 00 00 48 89 84 24 d8 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 8c 24 e0 00 00 00 48 89 84 24 e8 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 84 24 f0 00 00 00 b8 0c 00 00 00 48 89 84 24 f8 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 8c 24 00 01 00 00 48 89 84 24 08 01 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 8c 24 10 01 00 00 48 89 84 24 18 01 00 00 ?? ?? ?? ?? 48 89 7c 24 58 48 89 9c 24 48 01 00 00 48 89 5c 24 60 48 89 7c 24 68 48 89 6c 24 70 48 83 64 24 78 00 48 89 bc 24 80 00 00 00 49 89 fc}  //weight: 1, accuracy: Low
        $x_1_2 = "NTLMsrc\\soliloquy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


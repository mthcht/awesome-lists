rule VirTool_Win64_Bypasz_A_2147959642_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypasz.A"
        threat_id = "2147959642"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypasz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b cb ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 05 fd 42 00 00 48 85 c0 ?? ?? 48 89 84 24 88 00 00 00 48 8b 84 24 b0 00 00 00 48 25 ff ff f0 ff 48 89 ac 24 a8 00 00 00 48 83 c8 01 48 89}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b cb e8 ?? ?? ?? ?? 48 8b 8b 98 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ba fe ff fe ff ff 7f 00 00 48 3b ca}  //weight: 1, accuracy: Low
        $x_1_3 = {57 48 83 ec 20 48 8b d9 48 8b 89 98 00 00 00 e8 ?? ?? ?? ?? 48 8b f8 48 8b d0 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 ff ?? ?? ba 04 00 00 00 48 8b cf ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


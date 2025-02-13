rule VirTool_Win64_Voidgate_A_2147914757_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Voidgate.A"
        threat_id = "2147914757"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Voidgate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 41 b8 d0 04 00 00 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 84 24 80 00 00 00 10 00 10 00 ff ?? ?? ?? ?? ?? 48 8b d8 ?? ?? ?? ?? ?? 48 8b c8 ff ?? ?? ?? ?? ?? 48 89 b4 24 98 00 00 00 48 8b 8c 24 c0 00 00 00 48 81 e1 ff ff fc ff 48 83 c9 01 48 89 8c 24 c0 00 00 00 c7 84 24 80 00 00 00 10 00 10 00 ?? ?? ?? ?? ?? 48 8b cb ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 bb 32 a2 df 2d 99 2b 00 00 48 3b c3 ?? ?? 48 83 65 10 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b 45 10 48 89 45 f0 ff ?? ?? ?? ?? ?? 8b c0 48 31 45 f0 ff ?? ?? ?? ?? ?? 8b c0 ?? ?? ?? ?? 48 31 45 f0 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


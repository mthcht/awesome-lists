rule VirTool_Win64_RemotePot_A_2147914758_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/RemotePot.A"
        threat_id = "2147914758"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "RemotePot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 54 24 40 ?? ?? ?? ?? ?? ?? ?? 45 33 c0 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 ?? ?? ?? ?? ?? ?? eb ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 45 33 c0 ba d2 04 00 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 c0 ff ff ff ff 48 ff c0 66 83 3c 41 00 ?? ?? 48 83 f8 02 ?? ?? 48 ?? ?? ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 bc 24 40 02 00 00 c7 05 42 e2 02 00 01 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 11 45 80 0f 11 45 ?? e8 ?? ?? ?? ?? 4c ?? ?? ?? 4c ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 45 33 c9 c7 05 b0 08 03 00 01 00 00 00 41 b8 00 20 00 00 ?? ?? ?? ?? 49 8b cf ff ?? ?? ?? ?? ?? 83 f8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


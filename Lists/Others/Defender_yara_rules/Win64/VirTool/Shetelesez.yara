rule VirTool_Win64_Shetelesez_A_2147955140_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shetelesez.A"
        threat_id = "2147955140"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shetelesez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 ac 24 80 00 00 00 33 d2 48 8b cf 48 89 b4 24 88 00 00 00 c7 44 24 20 04 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 4c 8b c5 ?? ?? ?? ?? ?? ?? 48 8b f0 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 4c 8b cd 4d 8b c6 48 89 5c 24 20 48 8b d6 48 8b cf ?? ?? ?? ?? ?? ?? 85 c0 [0-32] 48 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b c3 33 d2 b9 ff ff 1f 00 ?? ?? ?? ?? ?? ?? 48 8b f8 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


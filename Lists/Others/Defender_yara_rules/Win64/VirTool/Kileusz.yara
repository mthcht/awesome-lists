rule VirTool_Win64_Kileusz_A_2147965078_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kileusz.A"
        threat_id = "2147965078"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kileusz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 89 5c 24 40 48 89 7c 24 30 ?? ?? ?? ?? ?? ?? ?? 89 7c 24 28 45 33 c9 45 33 c0 c7 44 24 20 03 00 00 00 ba 00 00 00 c0 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b cb ff ?? ?? ?? ?? ?? b9 ?? ?? 00 00 ff ?? ?? ?? ?? ?? 44 8b 44 24 40 33 d2 b9 00 04 00 00 ff ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 7c 24 38 ?? ?? ?? ?? ?? 48 89 44 24 30 ?? ?? ?? ?? ?? 89 7c 24 28 41 b9 04 00 00 00 ba 24 20 22 00 48 89 7c 24 20 48 8b cb ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


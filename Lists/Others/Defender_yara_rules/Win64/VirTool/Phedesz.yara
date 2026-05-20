rule VirTool_Win64_Phedesz_A_2147969784_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Phedesz.A"
        threat_id = "2147969784"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Phedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b f8 33 c0 b9 60 00 00 00 f3 aa 48 c7 44 24 70 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 28 c7 44 24 20 01 00 00 00 41 b9 02 00 00 00 45 33 c0 ba ff 01 0f 00 48 8b 8c 24 10 01 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8c 24 10 01 00 00 e8 ?? ?? ?? ?? 85 c0 ?? ?? 41 b9 04 00 00 00 ?? ?? ?? ?? ?? ba 0c 00 00 00 48 8b 4c 24 60 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 ec 48 48 c7 44 24 28 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c9 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 [0-23] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


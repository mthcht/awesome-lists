rule VirTool_Win64_MiniLoader_A_2147939704_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MiniLoader.A"
        threat_id = "2147939704"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MiniLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 08 48 8b 45 30 48 8b 10 8b 45 fc 48 01 d0 44 89 ca 31 ca 88 10 48 8b 45 30 48 8b 48 20 8b 55 fc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 fc 48 89 d0 48 c1 e0 04 48 29 d0 48 c1 e0 03 48 89 c2 48 8b 45 f0 48 01 c2 0f b6 45 20 88 42 14 8b 55 fc 48 89 d0 48 c1 e0 04 48 29 d0 48 c1 e0 03 48 89 c2 48 8b 45 f0 48 01 d0 c7 40 10 00 00 00 00 83 45 fc 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


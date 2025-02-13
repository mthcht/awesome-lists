rule HackTool_Win64_KrakenMask_A_2147928580_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/KrakenMask.A"
        threat_id = "2147928580"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "KrakenMask"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 40 3c 48 8b 8d 20 01 00 00 8b 44 01 50 83 e8 02 8b c0 48 39 45 28 ?? ?? 48 8b 45 28 48 8b 8d 20 01 00 00 48 03 c8 48 8b c1 41 b8 02 00 00 00 ?? ?? ?? ?? 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 40 3c 48 8b 8d 30 01 00 00 8b 44 01 50 83 e8 0c 8b c0 48 39 45 38 ?? ?? 48 8b 45 38 48 8b 8d 30 01 00 00 48 03 c8 48 8b c1 41 b8 0c 00 00 00 ?? ?? ?? ?? 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 85 48 19 00 00 48 8b 85 58 19 00 00 48 8b 8d 08 2e 00 00 48 89 08 48 8b 85 c8 2d 00 00 48 89 85 a8 1e 00 00 48 8b 05 ?? ?? ?? ?? 48 89 85 60 1e 00 00 48 8b 85 c8 35 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 85 e8 2e 00 00 48 8b 85 e8 2e 00 00 48 05 00 10 00 00 48 89 85 e8 2e 00 00 41 b8 00 50 00 00 ba 08 00 00 00 48 8b 8d c8 2e 00 00 ff 15 ?? ?? ?? ?? 48 89 85 08 2f 00 00 48 8b 85 08 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


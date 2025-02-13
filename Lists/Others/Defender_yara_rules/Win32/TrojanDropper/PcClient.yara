rule TrojanDropper_Win32_PcClient_A_2147646029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/PcClient.A"
        threat_id = "2147646029"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 5c 52 25 63 6d 25 63 74 25 63 43 2e 64 6c 6c 00 00 00 52 73 54 72 41 79 2e 65 58 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 30 8b 0c 3e 03 f7 8b e9 2b 6a 1c 8d 42 1c 83 c4 18 3b 6a 38 73 ?? 8b 28 8b 54 24 1c 8b 44 24 30 2b cd 03 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


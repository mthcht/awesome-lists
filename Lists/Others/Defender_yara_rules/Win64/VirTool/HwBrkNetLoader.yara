rule VirTool_Win64_HwBrkNetLoader_A_2147931567_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/HwBrkNetLoader.A"
        threat_id = "2147931567"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HwBrkNetLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fa 48 d3 e7 8d 48 ?? 48 d3 e2 48 0b fa 48 f7 d7 48 23 bc 24 90 00 00 00 4c 0f ab c7 48 89 bc 24}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 80 98 00 00 00 48 8b 48 30 48 8b 10 33 c0 89 01 49 83 80 98 00 00 00 08 49 89 40 78}  //weight: 1, accuracy: High
        $x_1_3 = {49 89 80 98 00 00 00 33 c0 49 89 40 78 b8 ff ff ff ff 48 8b 5c 24 30 48 83 c4 20 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


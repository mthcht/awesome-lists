rule VirTool_Win64_PplFault_A_2147890083_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/PplFault.A"
        threat_id = "2147890083"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PplFault"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c0 48 8b ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 45 33 c9 45 33 c0 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 ec 38 41 b8 04 00 00 00 33 d2 b9 ff ff 1f}  //weight: 1, accuracy: High
        $x_1_3 = {40 53 48 83 ec ?? 48 8b 51 ?? 48 8b d9 48 83 fa ?? 72 2c 48 8b 09 48 ff c2 48 81 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


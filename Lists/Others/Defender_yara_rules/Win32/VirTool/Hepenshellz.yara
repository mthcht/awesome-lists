rule VirTool_Win32_Hepenshellz_B_2147844676_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Hepenshellz.B!MTB"
        threat_id = "2147844676"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hepenshellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d0 50 68 dc ?? ?? ?? 8b 4d ac 51 ff 15 ?? ?? ?? ?? 3b f4}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 88 00 00 00 00 8b f4 8d ?? ?? 50 8b 4d 94 51 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 4c ff ff ff 03 85 58 ff ff ff 50 8b 8d 4c ff ff ff 51 83 ec 0c 8b f4 89 a5 20 fe ff ff 8d ?? ?? ?? ?? ?? 52}  //weight: 1, accuracy: Low
        $x_1_4 = {50 8b 85 28 ff ff ff 50 8b 8d 04 ff ff ff 51 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win32_LzDump_B_2147839548_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/LzDump.B!MTB"
        threat_id = "2147839548"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LzDump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 08 8b fc ff 15 ?? ?? ?? ?? 3b fc e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 85 c0 74 79 c7 45 d0 04 00 00 00 8b f4 8d 45 ?? 50 6a 04 8d 4d ?? 51 6a 14 8b 55 e8 52 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c4 0c c7 85 a8 fd ff ff 2c 02 00 00 c7 85 9c fd ff ff 14 ae 42 00 8d 85 ?? ?? ?? ?? 50 8b 4d dc 51 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 85 7c ff ff ff 00 00 00 00 c7 85 6c ff ff ff 00 00 00 00 c7 85 70 ff ff ff 00 00 00 00 c6 85 63 ff ff ff 01 8b f4 8d 85 ?? ?? ?? ?? 50 6a 20 8b fc ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 85 58 ff ff ff 50 8b 4d b8 51 8b 95 40 ff ff ff 52 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


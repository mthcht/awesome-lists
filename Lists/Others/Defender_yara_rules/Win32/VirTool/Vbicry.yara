rule VirTool_Win32_Vbicry_A_2147628238_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbicry.A"
        threat_id = "2147628238"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbicry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 e4 0f b6 00 89 45 e0 81 7d e0 00 01 00 00 73 06 83 65 b8 00 eb 08 e8 ?? ?? ff ff 89 45 b8 8b 45 e0 c1 e0 08 8b 4d dc 03 c8 a1 ?? ?? ?? ?? 66 0f b6 04 08 66 a3 ?? ?? ?? ?? 0f bf 05 ?? ?? ?? ?? 89 45 e4 81 7d e4 00 01 00 00 73 06 83 65 b4 00 eb 08}  //weight: 1, accuracy: Low
        $x_1_2 = "DoNotAllowExceptions\" /t REG_DWORD /d \"0\" /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


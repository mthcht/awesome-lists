rule VirTool_Win32_Belesz_A_2147970843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Belesz.A"
        threat_id = "2147970843"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Belesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e0 00 00 00 00 50 56 ff ?? ?? ?? ?? ?? 8b 45 e0 3b 45 0c ?? ?? 6a 00 56 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 68 ?? ?? 00 10 6a 00 6a 00 ff ?? ?? ?? ?? ?? 48 83 f8 fe ?? ?? c7 45 f0 00 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


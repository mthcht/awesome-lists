rule VirTool_Win32_Keylogger_A_2147639081_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Keylogger.A"
        threat_id = "2147639081"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 64 7f 5d 0f 84 ?? 00 00 00 83 f8 2e 7f 3b 0f 84 ?? ?? 00 00 83 f8 0d 7f 19 0f 84 ?? ?? 00 00 83 e8 09 0f 84 ?? ?? 00 00 83 e8 03}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 9b 83 f8 09 0f 87 ?? ?? 00 00 ff 24 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


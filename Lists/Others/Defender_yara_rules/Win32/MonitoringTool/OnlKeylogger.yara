rule MonitoringTool_Win32_OnlKeylogger_162185_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/OnlKeylogger"
        threat_id = "162185"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "OnlKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 65 79 6c 6f 67 67 65 72 4f 6e 6c 69 6e 65 2e 63 6f 6d 00}  //weight: 2, accuracy: High
        $x_2_2 = {4b 65 79 6c 6f 67 67 65 72 20 76 32 33 00}  //weight: 2, accuracy: High
        $x_1_3 = {4b 65 79 6c 6f 67 67 65 72 20 44 65 61 63 74 69 76 61 74 65 64 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 65 61 63 74 69 76 61 74 65 64 20 4b 65 79 6c 6f 67 67 65 72 21 00}  //weight: 1, accuracy: High
        $x_2_5 = "\\sessionstore.js" ascii //weight: 2
        $x_2_6 = {68 00 02 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 50 68 ?? ?? ?? ?? 6a 0d e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 78 6a 03 68 bb bb aa 0a 6a 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


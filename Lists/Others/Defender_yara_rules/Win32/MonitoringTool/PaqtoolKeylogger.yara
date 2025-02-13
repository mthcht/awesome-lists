rule MonitoringTool_Win32_PaqtoolKeylogger_17560_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PaqtoolKeylogger"
        threat_id = "17560"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PaqtoolKeylogger"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Do you really want to close Paq KeyLog" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 70 61 71 74 6f 6f 6c 2e 63 6f 6d 2f 70 72 6f 64 75 63 74 2f 6b 65 79 6c 6f 67 2f 6b 65 79 6c 6f 67 5f ?? ?? ?? 2e 68 74 6d}  //weight: 1, accuracy: Low
        $x_3_3 = {59 6f 75 20 68 61 76 65 20 61 6c 72 65 61 64 79 20 73 74 61 72 74 65 64 20 4b 65 79 6c 6f 67 2e ?? ?? ?? ?? 6f 6e 65 49 6e 73 74 61 6e 63 65 4d 75 74 65 78 74 50 61 71 4b 65 79 4c 6f 67}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


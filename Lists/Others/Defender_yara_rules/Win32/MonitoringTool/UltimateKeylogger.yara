rule MonitoringTool_Win32_UltimateKeylogger_150665_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/UltimateKeylogger"
        threat_id = "150665"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UltimateKeylogger"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 75 6c 6b 6c 66 65 6d 6f 6e 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_1_2 = "KeyHook" ascii //weight: 1
        $x_1_3 = "\\SilentKey" ascii //weight: 1
        $x_1_4 = {00 75 6b 66 72 65 65 2e 63 66 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_UltimateKeylogger_150665_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/UltimateKeylogger"
        threat_id = "150665"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UltimateKeylogger"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 4c 4b 6c 4d 6f 6e 2e 64 6c 6c 00 3f 41 64 64 4b 65 79 45 6e 74 72 79 40 [0-255] 50 41 55 74 61 67 4b 65 79 52 65 73 75 6c 74}  //weight: 1, accuracy: Low
        $x_1_2 = "KeyHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_UltimateKeylogger_150665_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/UltimateKeylogger"
        threat_id = "150665"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UltimateKeylogger"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "evaluation copy of Ultimate Keylogger has EXPIRED!" ascii //weight: 1
        $x_1_2 = "contact support@ultimatekeylogger.com" ascii //weight: 1
        $x_1_3 = "include your License Key in ukl.ini file." ascii //weight: 1
        $x_1_4 = "passwords you typed do not mutch." ascii //weight: 1
        $x_1_5 = "Q2hpbGthdCBTb2Z0d2FyZSwgSW5jLg==" ascii //weight: 1
        $x_1_6 = "KRyLack Keylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


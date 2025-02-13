rule MonitoringTool_Win32_KeyloggerOnline_162108_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/KeyloggerOnline"
        threat_id = "162108"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyloggerOnline"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 bd c0 fd ff ff 49 45 46 72 75}  //weight: 2, accuracy: High
        $x_2_2 = {81 bd c0 fd ff ff 43 68 72 6f 75}  //weight: 2, accuracy: High
        $x_2_3 = {81 bd c0 fd ff ff 4d 6f 7a 69 75}  //weight: 2, accuracy: High
        $x_2_4 = {8b 75 10 ad ad c1 e0 10 91 ad c1 e0 18 0b c8}  //weight: 2, accuracy: High
        $x_2_5 = "KeyloggerOnline.com" ascii //weight: 2
        $x_1_6 = "Disabled Keylogger!" ascii //weight: 1
        $x_1_7 = "Global\\tm-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}


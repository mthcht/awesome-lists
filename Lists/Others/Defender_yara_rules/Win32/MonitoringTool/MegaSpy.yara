rule MonitoringTool_Win32_MegaSpy_164437_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MegaSpy"
        threat_id = "164437"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MegaSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 13 05 32 81 91 14 a1 b1 42 23 c1 52 d1 f0 33}  //weight: 1, accuracy: High
        $x_1_2 = {c4 d4 e4 f4 a5 b5 c5 d5 e5 f5 56 66 76 86 96 a6}  //weight: 1, accuracy: High
        $x_1_3 = "do Mega-Spy expirou" ascii //weight: 1
        $x_1_4 = "Mega-Spy novamente utilize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


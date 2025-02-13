rule MonitoringTool_Win32_TektonIt_222279_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/TektonIt"
        threat_id = "222279"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TektonIt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-d %appdata%\\Windows\\control" ascii //weight: 10
        $x_1_2 = "run.bat" wide //weight: 1
        $x_1_3 = "b2b2etempfile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_TektonIt_222279_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/TektonIt"
        threat_id = "222279"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TektonIt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ",/c build\\data.exe -p7L34MF845JMHY0 -d C:\\Log" ascii //weight: 1
        $x_1_2 = {b8 10 80 40 00 a3 ?? ?? ?? ?? b8 30 80 40 00 a3 ?? ?? ?? ?? b8 ?? ?? 40 00 a3 ?? ?? ?? ?? b8 10 14 40 00 a3 ?? ?? ?? ?? a0 60 80 40 00 a2 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule MonitoringTool_Win64_RefogKeylogger_205590_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win64/RefogKeylogger"
        threat_id = "205590"
        type = "MonitoringTool"
        platform = "Win64: Windows 64-bit platform"
        family = "RefogKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "z:\\Projects\\ReleaseRepository\\MonitorProject\\Delphi\\Distr\\RefogMonitor\\Mpk64.pdb" ascii //weight: 1
        $x_1_2 = "MUTEX_PROGRAMM_RUNNING:MPK64_LOADER" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win64_RefogKeylogger_205590_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win64/RefogKeylogger"
        threat_id = "205590"
        type = "MonitoringTool"
        platform = "Win64: Windows 64-bit platform"
        family = "RefogKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mpk64.dll" ascii //weight: 1
        $x_1_2 = "WM_IMHOOK_KG" ascii //weight: 1
        $x_1_3 = "WM_MOUSEMOVEHOOK_KG" ascii //weight: 1
        $x_1_4 = "Refog Inc" ascii //weight: 1
        $x_4_5 = "GET /im/sendIM?comscoreChannel" wide //weight: 4
        $x_4_6 = "<Ymsg Command=\"6\"" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


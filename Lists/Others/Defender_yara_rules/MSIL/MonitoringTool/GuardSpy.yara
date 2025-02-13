rule MonitoringTool_MSIL_GuardSpy_213526_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/GuardSpy"
        threat_id = "213526"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GuardSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "D:\\Guard Spy setup original\\Guard Spy setup\\obj\\x86\\Release\\Guard Spy setup esp.pdb" ascii //weight: 2
        $x_1_2 = "cmd.exe /c start  http://www.monitoreatufamilia.com" wide //weight: 1
        $x_1_3 = "C:\\mysql\\ext.exe" wide //weight: 1
        $x_1_4 = "Guard___Spy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


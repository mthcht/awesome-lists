rule MonitoringTool_MSIL_BassemRat_233508_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/BassemRat"
        threat_id = "233508"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BassemRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nj-q8" wide //weight: 1
        $x_1_2 = "Listening On Port : ----" wide //weight: 1
        $x_1_3 = "Kaylogger -" wide //weight: 1
        $x_1_4 = "\\Stub.exe" wide //weight: 1
        $x_1_5 = "Zaki - Bassem" wide //weight: 1
        $x_1_6 = "Server Online [x]" wide //weight: 1
        $x_1_7 = "Bassem HAcker Rat" wide //weight: 1
        $x_1_8 = "Nihro RAT" wide //weight: 1
        $x_1_9 = "Execute|BawaneH|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


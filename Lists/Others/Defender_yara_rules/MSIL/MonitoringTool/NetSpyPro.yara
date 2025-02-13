rule MonitoringTool_MSIL_NetSpyPro_183399_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/NetSpyPro"
        threat_id = "183399"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetSpyPro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "240"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "NetSpyPro\\NSPro\\NSPro" ascii //weight: 100
        $x_100_2 = "wtsoftware.com.br/" ascii //weight: 100
        $x_20_3 = "netspypro-ajuda.htm" ascii //weight: 20
        $x_20_4 = "get_NSPro_SerialWS_valida_serial" ascii //weight: 20
        $x_20_5 = {67 65 74 5f 66 61 63 65 62 6f 6f 6b 32 00 67 65 74 5f 6d 73 6e}  //weight: 20, accuracy: High
        $x_10_6 = "msnspy.com.br/admin/valida-serial.asmx" ascii //weight: 10
        $x_10_7 = "chkKeyLogger_CheckedChanged" ascii //weight: 10
        $x_10_8 = "WebBlocker_CheckedChanged" ascii //weight: 10
        $x_10_9 = "txtKeyLoggerKeyWords" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 4 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}


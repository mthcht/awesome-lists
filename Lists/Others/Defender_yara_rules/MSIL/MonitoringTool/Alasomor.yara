rule MonitoringTool_MSIL_Alasomor_A_232545_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Alasomor.A"
        threat_id = "232545"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Alasomor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_Keyboard_Activity_" wide //weight: 1
        $x_1_2 = "_Screen_Activity_" wide //weight: 1
        $x_1_3 = "_Password_Activity_" wide //weight: 1
        $x_1_4 = "GetChromePasswords" ascii //weight: 1
        $x_1_5 = "GetComodoPasswords" ascii //weight: 1
        $x_1_6 = "GetFlockPasswords" ascii //weight: 1
        $x_1_7 = "GetOperaPasswords" ascii //weight: 1
        $x_1_8 = "GetYandexPasswords" ascii //weight: 1
        $x_1_9 = "GetIEPasswords" ascii //weight: 1
        $x_1_10 = "GetOutlookPasswords" ascii //weight: 1
        $x_1_11 = "GetThunderbirdPasswords" ascii //weight: 1
        $x_1_12 = "GetFirefoxPasswords" ascii //weight: 1
        $x_1_13 = "SendKeyboardRecords" ascii //weight: 1
        $x_1_14 = "SendPasswordRecords" ascii //weight: 1
        $x_1_15 = "SendScreenRecords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}


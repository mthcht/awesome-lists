rule TrojanSpy_MSIL_Xmatlog_A_2147688966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Xmatlog.A"
        threat_id = "2147688966"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmatlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[xMaterdom]" wide //weight: 1
        $x_1_2 = "/C net stop MpsSvc" wide //weight: 1
        $x_1_3 = "DisableRegistryTools" wide //weight: 1
        $x_1_4 = "Mater-Logger-Log" wide //weight: 1
        $x_1_5 = "xMaterLogger_Stub" ascii //weight: 1
        $x_1_6 = "sy32kopyalamametod" ascii //weight: 1
        $x_1_7 = "Loglarigonder" ascii //weight: 1
        $x_1_8 = "regengellememetodu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


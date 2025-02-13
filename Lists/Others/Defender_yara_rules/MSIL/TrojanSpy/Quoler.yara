rule TrojanSpy_MSIL_Quoler_A_2147706320_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Quoler.A"
        threat_id = "2147706320"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quoler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RVRmMmQa1EY" wide //weight: 1
        $x_1_2 = "ooffice287@gmail.com" wide //weight: 1
        $x_1_3 = "info@theadvertiser.biz" wide //weight: 1
        $x_1_4 = "Quotation10210 started at: " wide //weight: 1
        $x_1_5 = "DisableTaskMgr" wide //weight: 1
        $x_1_6 = "DisableRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


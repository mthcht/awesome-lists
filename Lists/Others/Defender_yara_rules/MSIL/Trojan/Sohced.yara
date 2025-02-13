rule Trojan_MSIL_Sohced_A_2147845479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sohced.A!MTB"
        threat_id = "2147845479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sohced"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "U0VMRUNUICogRlJPTSBXaW4zMl9Qcm9jZXNzb3I=" wide //weight: 2
        $x_2_2 = "U0VMRUNUICogRlJPTSBXaW4zMl9WaWRlb0NvbnRyb2xsZXI=" wide //weight: 2
        $x_2_3 = "KDMyIEJpdCk=" wide //weight: 2
        $x_2_4 = "VW5rbm93" wide //weight: 2
        $x_2_5 = "SWRlbnRpZmllcg==" wide //weight: 2
        $x_2_6 = "Ly9pcGFwaS5jby9" wide //weight: 2
        $x_2_7 = "VG90YWxQaHlzaWNhbE1lbW9yeQ==" wide //weight: 2
        $x_2_8 = "cm9vdFxDSU1WMg==" wide //weight: 2
        $x_2_9 = "U2VsZWN0ICogRnJvbSBXaW4zMl9Db21wdXRlclN5c3RlbQ==" wide //weight: 2
        $x_2_10 = "U0VMRUNUIFByb2Nlc3NvcklkIEZST00gV2luMzJfUHJvY2Vzc29y" wide //weight: 2
        $x_2_11 = "UHJvY2Vzc29ySWQ=" wide //weight: 2
        $x_2_12 = "KDY0IEJpdCk=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


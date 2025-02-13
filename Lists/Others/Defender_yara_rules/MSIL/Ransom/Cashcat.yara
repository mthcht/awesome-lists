rule Ransom_MSIL_Cashcat_SA_2147774143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cashcat.SA!MTB"
        threat_id = "2147774143"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cashcat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENABLING CAT MODE!" ascii //weight: 1
        $x_1_2 = "CashCat has encrypted your files!" ascii //weight: 1
        $x_1_3 = "CashCatRansomwareSimulator" ascii //weight: 1
        $x_1_4 = "pay the Ransom!" ascii //weight: 1
        $x_1_5 = "CashCat Started!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


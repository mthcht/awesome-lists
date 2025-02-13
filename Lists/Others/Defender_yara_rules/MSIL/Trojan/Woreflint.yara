rule Trojan_MSIL_Woreflint_ABF_2147782677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Woreflint.ABF!MTB"
        threat_id = "2147782677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Woreflint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0b 04 17 da 0c 16 0a 2b 0a 07 03 06 94 d6 0b 06 17 d6 0a 06 08 31 f2 07 6c 04 6c 5b 02 02}  //weight: 10, accuracy: High
        $x_3_2 = "getAverage" ascii //weight: 3
        $x_3_3 = "kayitSayisi" ascii //weight: 3
        $x_3_4 = "sqlCalistir" ascii //weight: 3
        $x_3_5 = "dsGetir" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


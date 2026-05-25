rule Ransom_MSIL_NOTPERRY_AMTB_2147970087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NOTPERRY!AMTB"
        threat_id = "2147970087"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NOTPERRY"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NotPerryRansomware" ascii //weight: 1
        $x_1_2 = "NOTPERRY - FILES ENCRYPTED" ascii //weight: 1
        $x_1_3 = ".notperry" ascii //weight: 1
        $x_1_4 = "READ_ME_NOTPERRY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


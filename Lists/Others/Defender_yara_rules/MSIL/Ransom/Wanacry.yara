rule Ransom_MSIL_Wanacry_B_2147786658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Wanacry.B!MTB"
        threat_id = "2147786658"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wanacry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Files Have been encrypted" ascii //weight: 1
        $x_1_2 = "ShareWare_Ransomware" ascii //weight: 1
        $x_1_3 = "Wanacrytor" ascii //weight: 1
        $x_1_4 = "Ethereum Adress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


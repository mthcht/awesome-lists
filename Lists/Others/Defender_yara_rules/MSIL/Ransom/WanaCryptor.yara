rule Ransom_MSIL_WanaCryptor_PAA_2147786663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WanaCryptor.PAA!MTB"
        threat_id = "2147786663"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WanaCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/create /sc minute /mo 1 /tn PolicyUpdate /tr \"" wide //weight: 1
        $x_1_2 = "Files Have been encrypted!!" wide //weight: 1
        $x_1_3 = "Wanacrytor" ascii //weight: 1
        $x_1_4 = "schtasks" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


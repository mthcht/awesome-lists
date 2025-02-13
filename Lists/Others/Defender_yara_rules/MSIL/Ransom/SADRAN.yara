rule Ransom_MSIL_SADRAN_DA_2147853296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SADRAN.DA!MTB"
        threat_id = "2147853296"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SADRAN"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_2 = "SAD RANSOMWARE" ascii //weight: 1
        $x_1_3 = "More information about Bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


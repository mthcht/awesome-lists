rule Ransom_MSIL_DonutCrypt_PA_2147961480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DonutCrypt.PA!MTB"
        threat_id = "2147961480"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".donut" wide //weight: 1
        $x_1_2 = "decrypt.txt" wide //weight: 1
        $x_3_3 = "files have been ENCRYPTED by DONUT Ransomware" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


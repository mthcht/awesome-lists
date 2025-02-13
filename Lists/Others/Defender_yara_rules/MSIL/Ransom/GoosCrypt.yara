rule Ransom_MSIL_GoosCrypt_PA_2147815448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/GoosCrypt.PA!MTB"
        threat_id = "2147815448"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GoosCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_wncry" ascii //weight: 1
        $x_1_2 = "Your files have been encrypted by the goose ransomware!" wide //weight: 1
        $x_1_3 = "\\sus.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


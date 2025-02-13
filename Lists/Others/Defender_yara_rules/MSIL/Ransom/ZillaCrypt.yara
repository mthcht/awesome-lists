rule Ransom_MSIL_ZillaCrypt_PA_2147808602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ZillaCrypt.PA!MTB"
        threat_id = "2147808602"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZillaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Crypt" wide //weight: 1
        $x_1_2 = "\\Crypt_Massage.txt" wide //weight: 1
        $x_1_3 = "Don't Worry Friends, You Can Restore All Your Files!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


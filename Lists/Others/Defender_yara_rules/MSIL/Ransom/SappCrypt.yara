rule Ransom_MSIL_SappCrypt_PA_2147765176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SappCrypt.PA!MTB"
        threat_id = "2147765176"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SappCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sapphire_Ransomware.Resources" wide //weight: 1
        $x_1_2 = "WScript.ShellA" wide //weight: 1
        $x_1_3 = ".sapphire" wide //weight: 1
        $x_1_4 = "YOUR FILES HAVE BEEN ENCRYPTED!!" wide //weight: 1
        $x_1_5 = "\\Sapphire Ransomware.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


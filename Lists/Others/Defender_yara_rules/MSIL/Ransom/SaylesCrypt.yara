rule Ransom_MSIL_SaylesCrypt_PA_2147795537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SaylesCrypt.PA!MTB"
        threat_id = "2147795537"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SaylesCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your computer has been infected by SayLess-Ransomware" wide //weight: 1
        $x_1_2 = "SAVE COMPUTER" wide //weight: 1
        $x_1_3 = {68 00 61 00 68 00 61 00 5f 00 50 00 4b 00 2e 00 36 00 36 00 36 00 2d 00 4e 00 4b 00 2d 00 4e 00 30 00 72 00 6d 00 c2 00 a1 00 45 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\SayLessRnm Window.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


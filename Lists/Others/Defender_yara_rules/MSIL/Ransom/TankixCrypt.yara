rule Ransom_MSIL_TankixCrypt_PA_2147837892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TankixCrypt.PA!MTB"
        threat_id = "2147837892"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TankixCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".TANKIX" wide //weight: 1
        $x_1_2 = "\\READ_ME.txt" wide //weight: 1
        $x_1_3 = "infected by Tanki X Ransomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


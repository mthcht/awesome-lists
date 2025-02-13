rule Ransom_MSIL_Lycheerypt_A_2147721694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lycheerypt.A"
        threat_id = "2147721694"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lycheerypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_Recover_Instructions." ascii //weight: 1
        $x_1_2 = "/C ping 1.1.1.1 -n 1 -w 1 > Nul & Del" ascii //weight: 1
        $x_1_3 = "MainFormRansom" wide //weight: 1
        $x_1_4 = "LightningCrypt" ascii //weight: 1
        $x_1_5 = ".LIGHTNING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


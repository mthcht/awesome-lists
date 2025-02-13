rule Ransom_MSIL_SapphireCrypt_PA_2147833615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SapphireCrypt.PA!MTB"
        threat_id = "2147833615"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SapphireCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sapphire_Ransomware" ascii //weight: 1
        $x_1_2 = "cmd /c vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_3 = ".fbi" wide //weight: 1
        $x_1_4 = "\\LOCKEDBYFBI.hta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


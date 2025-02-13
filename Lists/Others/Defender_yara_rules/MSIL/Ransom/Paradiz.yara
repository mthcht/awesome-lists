rule Ransom_MSIL_Paradiz_A_2147723993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Paradiz.A!bit"
        threat_id = "2147723993"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Paradiz"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<RSAKeyValue>" wide //weight: 1
        $x_1_2 = "/api/Encrypted.php" wide //weight: 1
        $x_1_3 = "vssadmin delete shadows /all" wide //weight: 1
        $x_1_4 = "*.paradise" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


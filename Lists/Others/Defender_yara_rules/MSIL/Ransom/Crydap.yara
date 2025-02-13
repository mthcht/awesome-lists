rule Ransom_MSIL_Crydap_A_2147709171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crydap.A"
        threat_id = "2147709171"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crydap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cryptowall.Properties" ascii //weight: 1
        $x_1_2 = "PadCrypt.pdb" ascii //weight: 1
        $x_1_3 = "Cryptowall\\bin\\Debug\\Obfuscated\\" ascii //weight: 1
        $x_1_4 = "PadCrypt.exe" ascii //weight: 1
        $x_1_5 = {24 66 61 30 37 38 30 64 33 2d 62 31 34 35 2d 34 32 34 33 2d 38 36 62 39 2d 66 31 63 36 62 37 62 38 61 31 32 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


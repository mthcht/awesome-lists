rule Ransom_MSIL_Detoxcrypt_A_2147716969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Detoxcrypt.A"
        threat_id = "2147716969"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Detoxcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DetoxCrypto\\DetoxCrypto\\obj\\Debug\\MicrosoftHost.pdb" ascii //weight: 1
        $x_1_2 = "detoxcrypto.net16.net/generate.php" ascii //weight: 1
        $x_1_3 = "\\Pokemon\\key.txt" ascii //weight: 1
        $x_1_4 = "\\Pokemon\\total.txt" ascii //weight: 1
        $x_1_5 = "No files choose!" ascii //weight: 1
        $x_1_6 = "<GetFiles>" ascii //weight: 1
        $x_1_7 = "\\Downloads\\Pokemon\\pokbg.jpg" ascii //weight: 1
        $x_1_8 = "\\Downloads\\Pokemon\\Pokemon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


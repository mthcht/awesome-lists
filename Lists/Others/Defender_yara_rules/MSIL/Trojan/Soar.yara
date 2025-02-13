rule Trojan_MSIL_Soar_A_2147649816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Soar.A"
        threat_id = "2147649816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Soar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SoraAdd.exe" wide //weight: 1
        $x_1_2 = "{3872a73d-48e1-4504-b393-a76428731afe}" wide //weight: 1
        $x_1_3 = "w3wp.exe" wide //weight: 1
        $x_1_4 = "ezM4NzJhNzNkLTQ4ZTEtNDUwNC1iMzkzLWE3NjQyODczMW" wide //weight: 1
        $x_1_5 = "\\CryptedFile.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


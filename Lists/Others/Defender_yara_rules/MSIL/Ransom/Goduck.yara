rule Ransom_MSIL_Goduck_2147729986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Goduck"
        threat_id = "2147729986"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Goduck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "|                       ALL I DECRYPT YOUR FILES WITH  MY  DECRYPTOR                    |" ascii //weight: 10
        $x_10_2 = "Program.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


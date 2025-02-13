rule Ransom_MSIL_Memekap_A_2147708293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Memekap.A"
        threat_id = "2147708293"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Memekap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DECRYPT_ReadMe" wide //weight: 1
        $x_1_2 = ".encrypted" wide //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_4 = "All your files encrypted with strong encryption." wide //weight: 1
        $x_1_5 = "You have 5 days to make transaction" wide //weight: 1
        $x_1_6 = ".tax201" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


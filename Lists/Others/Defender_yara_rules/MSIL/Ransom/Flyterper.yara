rule Ransom_MSIL_Flyterper_A_2147717254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Flyterper.A"
        threat_id = "2147717254"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Flyterper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Invoice\\HiDdEn-TeAr\\obj\\Debug\\invoice.pdb" ascii //weight: 10
        $x_10_2 = "SetWallpaperFromWeb" ascii //weight: 10
        $x_10_3 = "AES_Encrypt" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


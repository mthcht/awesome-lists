rule Ransom_MSIL_HASTU_DA_2147775157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HASTU.DA!MTB"
        threat_id = "2147775157"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HASTU"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HASTURamsoware" ascii //weight: 1
        $x_1_2 = "EncryptedKey" ascii //weight: 1
        $x_1_3 = "killswitch.php" ascii //weight: 1
        $x_1_4 = "wallpaper.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


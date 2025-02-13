rule Ransom_MSIL_Shezkrypt_A_2147726531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Shezkrypt.A"
        threat_id = "2147726531"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shezkrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 2
        $x_2_2 = "deleteMyProgram.bat" ascii //weight: 2
        $x_2_3 = ".sorry" ascii //weight: 2
        $x_2_4 = "c:\\Windows\\hrf.txt" ascii //weight: 2
        $x_2_5 = "All your files have been ENCRYPTED" ascii //weight: 2
        $x_2_6 = "systems@hitler.rocks" ascii //weight: 2
        $x_2_7 = "systems@tutanota.com" ascii //weight: 2
        $x_2_8 = "How Recovery Files.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


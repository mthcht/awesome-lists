rule Ransom_MSIL_Dowviki_A_2147726237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Dowviki.A"
        threat_id = "2147726237"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dowviki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".vindows" wide //weight: 2
        $x_2_2 = "this not microsoft vindows support" wide //weight: 2
        $x_2_3 = "call level 5 microsoft support technician at 1-844-609-3192" wide //weight: 2
        $x_2_4 = "files back for a one time charge of $349.99" wide //weight: 2
        $x_2_5 = "Vindows Locker" wide //weight: 2
        $x_2_6 = "Vindows.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


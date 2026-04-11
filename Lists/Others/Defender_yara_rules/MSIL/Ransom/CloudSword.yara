rule Ransom_MSIL_CloudSword_AMTB_2147966850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CloudSword!AMTB"
        threat_id = "2147966850"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CloudSword"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Viruses\\Malicious\\Rage\\Syndicate Winlocker (Hard)\\contu\\obj\\Release\\contu.pdb" ascii //weight: 1
        $x_1_2 = "\\Documents and Settings\\JohnDoe\\Application Data\\domination.lock" ascii //weight: 1
        $x_1_3 = "/delete /tn \"Realtek HD Audio Universal Service\" /f" ascii //weight: 1
        $x_1_4 = ".dominated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


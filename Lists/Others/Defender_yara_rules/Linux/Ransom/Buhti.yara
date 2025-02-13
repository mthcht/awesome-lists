rule Ransom_Linux_Buhti_A_2147847606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Buhti.A!MTB"
        threat_id = "2147847606"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Buhti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt_file" ascii //weight: 1
        $x_1_2 = "buhtiRansom" ascii //weight: 1
        $x_1_3 = "files are encrypted" ascii //weight: 1
        $x_1_4 = "restore all your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


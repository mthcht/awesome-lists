rule Ransom_Linux_Hellcat_A_2147926020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hellcat.A!MTB"
        threat_id = "2147926020"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hellcat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kill_all_vms" ascii //weight: 2
        $x_2_2 = "kill_vms" ascii //weight: 2
        $x_2_3 = "esxcli vm process kill --type=" ascii //weight: 2
        $x_1_4 = "Readme.%s.txt" ascii //weight: 1
        $x_1_5 = "b_skip_some_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


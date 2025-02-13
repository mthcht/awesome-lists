rule Ransom_Linux_Rustomware_A_2147848892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Rustomware.A!MTB"
        threat_id = "2147848892"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Rustomware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "README_Rustsomware" ascii //weight: 2
        $x_2_2 = "rustsomware <encrypt" ascii //weight: 2
        $x_1_3 = "Dropped ransom message" ascii //weight: 1
        $x_1_4 = "unwind_gettextrelbase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


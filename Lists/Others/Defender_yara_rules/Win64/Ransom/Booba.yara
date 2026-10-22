rule Ransom_Win64_Booba_AMTB_2147980796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Booba!AMTB"
        threat_id = "2147980796"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Booba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Booba_readme.txt" ascii //weight: 3
        $x_3_2 = "booba_log.log" ascii //weight: 3
        $x_1_3 = "The Booba Team" ascii //weight: 1
        $x_1_4 = "Successfully deleted %lu shadow copies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


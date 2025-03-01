rule Trojan_AndroidOS_Evilinst_C_2147934497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Evilinst.C"
        threat_id = "2147934497"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Evilinst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PerformAdsSens" ascii //weight: 2
        $x_2_2 = "another_girl_in_the_wall_fb" ascii //weight: 2
        $x_2_3 = "SAVE_PER_PUSH_JOB" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


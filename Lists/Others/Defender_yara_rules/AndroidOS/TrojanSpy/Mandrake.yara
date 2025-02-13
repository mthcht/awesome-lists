rule TrojanSpy_AndroidOS_Mandrake_A_2147783539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mandrake.A"
        threat_id = "2147783539"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mandrake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/android/firmware/service/MainService;" ascii //weight: 2
        $x_2_2 = "Lcom/android/firmware/receiver/" ascii //weight: 2
        $x_2_3 = "pref_key_aup_seen" ascii //weight: 2
        $x_1_4 = "pref_key_def_asg_msg" ascii //weight: 1
        $x_1_5 = "pref_key_aup_counter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_AndroidOS_PJobRat_A_2147784704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PJobRat.A"
        threat_id = "2147784704"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PJobRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sp_key_screen_width" ascii //weight: 1
        $x_1_2 = {44 42 5f 52 45 46 5f 4f 4e 4c 49 4e 45 [0-1] 53 54 41 54 55 53}  //weight: 1, accuracy: Low
        $x_1_3 = "SeeYou.saveUserFcm.onSuccess()" ascii //weight: 1
        $x_1_4 = "see_you_prefs" ascii //weight: 1
        $x_1_5 = "isStoragePremGranted" ascii //weight: 1
        $x_1_6 = "CASE_APP_DB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_PJobRat_B_2147784705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PJobRat.B"
        threat_id = "2147784705"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PJobRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sp_key_screen_width" ascii //weight: 1
        $x_1_2 = "AppsDetailReceiver" ascii //weight: 1
        $x_1_3 = "powerSavedModeReceiver" ascii //weight: 1
        $x_1_4 = "jobs/JobContact;" ascii //weight: 1
        $x_1_5 = "observer/AudioObserver;" ascii //weight: 1
        $x_1_6 = "PROFILE_PIC_STORAGE_REF_NAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


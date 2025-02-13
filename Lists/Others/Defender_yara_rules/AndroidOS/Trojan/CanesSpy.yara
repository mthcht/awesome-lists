rule Trojan_AndroidOS_CanesSpy_A_2147896831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/CanesSpy.A"
        threat_id = "2147896831"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "CanesSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SUBSCRIPER_ID_SLOT_1" ascii //weight: 1
        $x_1_2 = "DEVICE_UNIQUE_IDShared" ascii //weight: 1
        $x_1_3 = "UPLOAD_FILES_NAMES_IN_DEVICE" ascii //weight: 1
        $x_1_4 = "STOP_UPLOAD_FILE_WAS_UPLOADED" ascii //weight: 1
        $x_1_5 = "Lcom/google/android/search/validate/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


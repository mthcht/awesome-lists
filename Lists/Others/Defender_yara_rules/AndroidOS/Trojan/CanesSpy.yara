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

rule Trojan_AndroidOS_CanesSpy_C_2147937880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/CanesSpy.C!MTB"
        threat_id = "2147937880"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "CanesSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 0e 16 00 08 07 15 00 54 70 f5 04 02 01 17 00 72 20 6a e3 10 00 0c 02 52 e1 6f 00 12 25 13 08 08 00 12 03 38 01 15 03 12 14 32 41 3e 00 32 51 4a 02 12 30 33 01 28 00 1f 0e f7 28 1f 02 93 2c 54 e9 5b a2 6e 20 0d b6 09 00 54 78 f6 04 54 80 b8 a2 54 26 2c a5 71 20 50 4f 60 00 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 08 ad 2c 38 08 c9 00 1f 00 ad 2c 5b 50 da a4 54 01 58 a5 1c 07 7d 35 33 71 2f 00 54 01 59 a5 13 02 e8 03 71 20 71 64 21 00 0c 10 52 01 57 a5 39 01 1e 00 54 00 5a a5 71 20 71 64 20 00 0c 11 14 12 ab 01 08 7f 13 13 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


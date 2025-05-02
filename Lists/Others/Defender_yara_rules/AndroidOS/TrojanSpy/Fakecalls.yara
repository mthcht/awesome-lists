rule TrojanSpy_AndroidOS_Fakecalls_G_2147836836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecalls.G!MTB"
        threat_id = "2147836836"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "first_scanner_app" ascii //weight: 1
        $x_1_2 = "shouldOverrideUrlLoading" ascii //weight: 1
        $x_1_3 = "isScanningForOBQ" ascii //weight: 1
        $x_1_4 = "UNNECESSARY_AUTO_DELETE_LIST" ascii //weight: 1
        $x_1_5 = "KEY_IS_JUMP_TO_CLOSE_TCALL" ascii //weight: 1
        $x_1_6 = "CallLogBean{phone1=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecalls_B_2147838435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecalls.B!MTB"
        threat_id = "2147838435"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 68 61 6f 77 65 6e 30 [0-2] 2e 63 6f 6d}  //weight: 5, accuracy: Low
        $x_5_2 = {77 65 6e 64 69 6e 67 30 [0-2] 2e 63 6f 6d}  //weight: 5, accuracy: Low
        $x_1_3 = {50 68 6f 6e 65 43 61 6c 6c [0-8] 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_4 = {63 6f 6d 2f [0-8] 2f 72 74 6d 70 5f 63 6c 69 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_5 = "/device/gettransfer?number=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Fakecalls_L_2147923344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecalls.L!MTB"
        threat_id = "2147923344"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/applink/requestmaincall" ascii //weight: 1
        $x_1_2 = "/api/mobile/mobile_info" ascii //weight: 1
        $x_1_3 = "key_origin_package_name" ascii //weight: 1
        $x_1_4 = "chongpan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecalls_C_2147935650_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecalls.C!MTB"
        threat_id = "2147935650"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLICK_HIGH_PERMISSION_TIMES" ascii //weight: 1
        $x_1_2 = "IS_UPLOADING_CALL_LOG" ascii //weight: 1
        $x_1_3 = "REQUEST_UPLOAD_EXTRA_INFO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecalls_J_2147935651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecalls.J!MTB"
        threat_id = "2147935651"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/wish/defaultcallservice/activity/ValidActivitySKV" ascii //weight: 1
        $x_1_2 = {01 01 02 14 02 ?? 00 08 7f 6e 20 d5 00 21 00 0c 02 6e 20 ?? ?? 12 00 14 02 ?? 01 08 7f 6e 20 d5 00 21 00 0c 02 6e 20 ?? ?? 12 00 14 02 ?? 00 08 7f 6e 20 d5 00 21 00 0c 02 6e 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecalls_F_2147938560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecalls.F!MTB"
        threat_id = "2147938560"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 10 b9 01 02 00 0c 00 38 00 20 00 54 20 69 01 39 00 19 00 6e 10 be 01 02 00 0c 00 1f 00 d0 01 38 00 06 00 54 00 66 01 5b 20 69 01 54 20 69 01 39 00 09 00 22 00 9f 03 70 10 c2 1d 00 00 5b 20 69 01 54 20 69 01}  //weight: 1, accuracy: High
        $x_1_2 = {70 10 85 19 04 00 22 00 92 03 70 20 87 1d 40 00 5b 40 67 01 71 10 39 23 04 00 0c 00 5b 40 68 01 22 00 d5 01 22 01 cf 01 70 20 45 0d 41 00 70 20 5c 0d 10 00 5b 40 6a 01 6e 10 49 0d 04 00 0c 00 38 00 33 00 60 00 ff 00 13 01 13 00 34 10 0e 00 6e 10 49 0d 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecalls_N_2147940484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecalls.N!MTB"
        threat_id = "2147940484"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 00 0c 04 6e 20 ?? 02 43 00 0c 03 6e 20 ?? 02 13 00 0c 03 13 04 3a 00 6e 20 ?? 02 43 00 0c 03 62 04 03 00 6e 20 ?? 02 43 00 0c 03 13 04 20 00 6e 20 ?? 02 43 00 0c 03 60 04 02 00 6e 20 ?? 02 43 00 0c 03 13 04 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {06 00 0c 06 12 07 6e 30 ?? 01 69 07 0c 04 6e 10 ?? 02 04 00 0a 06 39 06 a4 00 6e 10 ?? 01 09 00 0c 02 6e 10 ?? 02 02 00 0a 06 39 06 98 00 6e 10 ?? 01 09 00 0c 00 6e 10 ?? 02 00 00 0a 06 39 06 8c 00 60 06 02 00 13 07 15 00 34 76 5f 00 6e 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


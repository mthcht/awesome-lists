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


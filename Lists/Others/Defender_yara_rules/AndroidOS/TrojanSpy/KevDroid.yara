rule TrojanSpy_AndroidOS_KevDroid_A_2147810566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/KevDroid.A"
        threat_id = "2147810566"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "KevDroid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Calllog.txt" ascii //weight: 1
        $x_1_2 = "/icloud/tmp-web.dat-enc" ascii //weight: 1
        $x_1_3 = "/sdcard/result-file.dat" ascii //weight: 1
        $x_1_4 = "?type=command&direction=receive&id=" ascii //weight: 1
        $x_1_5 = "MY_PERMISSIONS_REQUEST_NEEDEDPERMISSIONS" ascii //weight: 1
        $x_1_6 = "WEB_ENC_PATH" ascii //weight: 1
        $x_1_7 = "_exceptedExtensions" ascii //weight: 1
        $x_1_8 = "getAllSMSJSON" ascii //weight: 1
        $x_1_9 = "processImportantFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}


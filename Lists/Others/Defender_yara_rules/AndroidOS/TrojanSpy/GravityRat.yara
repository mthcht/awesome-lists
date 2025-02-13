rule TrojanSpy_AndroidOS_GravityRat_A_2147806271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GravityRat.A"
        threat_id = "2147806271"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GravityRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.android.whiskey.restart" ascii //weight: 1
        $x_1_2 = "sms_file_status" ascii //weight: 1
        $x_1_3 = "call_file_status" ascii //weight: 1
        $x_1_4 = "get_CD_CallsLogs" ascii //weight: 1
        $x_1_5 = "/Android/oww.txt" ascii //weight: 1
        $x_1_6 = "Location not available right now" ascii //weight: 1
        $x_1_7 = "androidsdkstream.com" ascii //weight: 1
        $x_1_8 = "hi back restarting!! :D" ascii //weight: 1
        $x_1_9 = "cl.log" ascii //weight: 1
        $x_1_10 = "/cdms.log" ascii //weight: 1
        $x_1_11 = "/ms.log" ascii //weight: 1
        $x_1_12 = "GetActivePrivateDomain" ascii //weight: 1
        $x_1_13 = "sosafe.co.in" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanSpy_AndroidOS_GravityRat_B_2147849839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GravityRat.B"
        threat_id = "2147849839"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GravityRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetActivePrivateDomain" ascii //weight: 2
        $x_2_2 = "call_file_status" ascii //weight: 2
        $x_2_3 = "Damn restarting12!! :D" ascii //weight: 2
        $x_2_4 = "sms_file_status" ascii //weight: 2
        $x_2_5 = "get_CD_CallsLogs" ascii //weight: 2
        $x_2_6 = "/jurassic/6c67d428.php" ascii //weight: 2
        $x_2_7 = "/hotriculture/671e00eb.php" ascii //weight: 2
        $x_1_8 = "/obb.log" ascii //weight: 1
        $x_1_9 = "/oww.log" ascii //weight: 1
        $x_1_10 = "cd_cl_log" ascii //weight: 1
        $x_1_11 = "cd_sm_log" ascii //weight: 1
        $x_1_12 = "/cdms.log" ascii //weight: 1
        $x_1_13 = "/location.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}


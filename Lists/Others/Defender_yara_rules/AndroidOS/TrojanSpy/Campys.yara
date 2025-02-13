rule TrojanSpy_AndroidOS_Campys_A_2147771620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Campys.A!MTB"
        threat_id = "2147771620"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Campys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://www.firmwaresystemupdate.com/hass" ascii //weight: 3
        $x_1_2 = "BACKGROUND_THREAD_KEEP_ALIVE_DURATION_MS" ascii //weight: 1
        $x_2_3 = "upload-file.php?uuid" ascii //weight: 2
        $x_1_4 = "answer.php" ascii //weight: 1
        $x_1_5 = "Record Call" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Campys_B_2147774004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Campys.B!MTB"
        threat_id = "2147774004"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Campys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "www.firmwaresystemupdate.com" ascii //weight: 2
        $x_1_2 = "upload-file.php" ascii //weight: 1
        $x_1_3 = "get-function.php" ascii //weight: 1
        $x_1_4 = "RecordCall" ascii //weight: 1
        $x_1_5 = "AllSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Campys_B_2147783229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Campys.B"
        threat_id = "2147783229"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Campys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AmService:setupLogging" ascii //weight: 1
        $x_1_2 = "Delete SMS success" ascii //weight: 1
        $x_1_3 = "Call record start for :" ascii //weight: 1
        $x_1_4 = "/upload-log.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Campys_C_2147824864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Campys.C!MTB"
        threat_id = "2147824864"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Campys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upload-file.php" ascii //weight: 1
        $x_1_2 = "get-function.php" ascii //weight: 1
        $x_1_3 = "amservice:setuplogging" ascii //weight: 1
        $x_1_4 = "recordcall" ascii //weight: 1
        $x_1_5 = "allsms" ascii //weight: 1
        $x_1_6 = "answer.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Campys_D_2147824865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Campys.D!MTB"
        threat_id = "2147824865"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Campys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pardis/book_name/list" ascii //weight: 1
        $x_1_2 = "runAfterScreenOn" ascii //weight: 1
        $x_1_3 = "ScreenControl" ascii //weight: 1
        $x_1_4 = "FileUploadTask" ascii //weight: 1
        $x_1_5 = "RecordAudioTask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


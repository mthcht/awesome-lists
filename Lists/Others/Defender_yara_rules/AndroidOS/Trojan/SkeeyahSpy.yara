rule Trojan_AndroidOS_SkeeyahSpy_Y_2147825898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SkeeyahSpy.Y"
        threat_id = "2147825898"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SkeeyahSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "uploadcallsrecord" ascii //weight: 10
        $x_10_2 = "uploadCallRecordings" ascii //weight: 10
        $x_10_3 = "uploadContact" ascii //weight: 10
        $x_10_4 = "contactsupload" ascii //weight: 10
        $x_10_5 = "uploadSms" ascii //weight: 10
        $x_10_6 = "smsupload" ascii //weight: 10
        $x_10_7 = "setKeylogs" ascii //weight: 10
        $x_10_8 = "getKeyLogs" ascii //weight: 10
        $x_1_9 = "uploadCallLog" ascii //weight: 1
        $x_1_10 = "getinstialldappslist" ascii //weight: 1
        $x_1_11 = "envoirmentAudios" ascii //weight: 1
        $x_1_12 = "uploadAudio" ascii //weight: 1
        $x_1_13 = "fn_getCamera" ascii //weight: 1
        $x_1_14 = "fn_getlocation" ascii //weight: 1
        $x_1_15 = "uploadListPath" ascii //weight: 1
        $x_1_16 = "delete_pass_date" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 5 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}


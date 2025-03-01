rule TrojanSpy_AndroidOS_FaceStealer_B_2147816931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FaceStealer.B!MTB"
        threat_id = "2147816931"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FaceStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/jdd/login/CheckLogin" ascii //weight: 1
        $x_1_2 = "mg.sl0.co/api/open/check_ck" ascii //weight: 1
        $x_1_3 = "UploadCookie" ascii //weight: 1
        $x_1_4 = "GetIpAddress" ascii //weight: 1
        $x_1_5 = "judgeIsLoginCookie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


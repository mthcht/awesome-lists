rule Trojan_AndroidOS_Greenbean_A_2147905471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Greenbean.A!MTB"
        threat_id = "2147905471"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Greenbean"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "org.icecream.greenbean" ascii //weight: 5
        $x_1_2 = "sendLockPattern" ascii //weight: 1
        $x_1_3 = "/monitorapi/api/v1/s3/uploadURL?signature=" ascii //weight: 1
        $x_1_4 = "hideRun" ascii //weight: 1
        $x_1_5 = "recInfo" ascii //weight: 1
        $x_1_6 = "OKWS_SEND_MESSAGE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


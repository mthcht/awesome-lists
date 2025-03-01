rule TrojanSpy_AndroidOS_SMSTheif_AU_2147848953_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSTheif.AU!MTB"
        threat_id = "2147848953"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/save_sms.php?from=" ascii //weight: 1
        $x_1_2 = "app.amex.express" ascii //weight: 1
        $x_1_3 = "getOriginatingAddress" ascii //weight: 1
        $x_1_4 = "SmsListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


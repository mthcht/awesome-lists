rule PUA_AndroidOS_Smsreg_A_330921_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:AndroidOS/Smsreg.A"
        threat_id = "330921"
        type = "PUA"
        platform = "AndroidOS: Android operating system"
        family = "Smsreg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ch/nth/android/utils/TelephonyUtils" ascii //weight: 1
        $x_1_2 = "verifySubscription" ascii //weight: 1
        $x_1_3 = "FIRST_SMS_SENT" ascii //weight: 1
        $x_1_4 = "scmsdk/async/ScmVerifySubscriptionRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


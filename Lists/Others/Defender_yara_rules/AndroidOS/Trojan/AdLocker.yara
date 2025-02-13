rule Trojan_AndroidOS_AdLocker_A_2147832433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AdLocker.A!MTB"
        threat_id = "2147832433"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AdLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.forcemellostudio.blurwallpaperfree.LockScreenService" ascii //weight: 1
        $x_1_2 = "startTrackingAppsFlyerEvent" ascii //weight: 1
        $x_1_3 = "startServerStatsUpdate" ascii //weight: 1
        $x_1_4 = "addAdvertiserIDData" ascii //weight: 1
        $x_1_5 = "getPhoneCallsCount" ascii //weight: 1
        $x_1_6 = "broadcastCardInfo" ascii //weight: 1
        $x_1_7 = "getLastSMSContact" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


rule Trojan_MacOS_FlexiSpy_C_2147793802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FlexiSpy.C!MTB"
        threat_id = "2147793802"
        type = "Trojan"
        platform = "MacOS: "
        family = "FlexiSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/Backup/FlexiSPY_macOS" ascii //weight: 10
        $x_10_2 = "com.applle.queue.keyboardlogger" ascii //weight: 10
        $x_10_3 = "[AppProcessKilledNotifier registerAppProcess]" ascii //weight: 10
        $x_10_4 = "[PageVisitedNotifier startNotify]" ascii //weight: 10
        $x_10_5 = "%@ {mAppBundle : %@, mAppName : %@, mKeyStroke : %@, mKeyStrokeDisplay : %@, mWindowTitle : %@, mUrl : %@, mFrontmostWindow : %@}" ascii //weight: 10
        $x_10_6 = "select * from moz_places where id in (select place_id from moz_historyvisits where visit_date = (select max(visit_date) from moz_historyvisits))" ascii //weight: 10
        $x_1_7 = "/ScreenshotUtils.m" ascii //weight: 1
        $x_1_8 = "/FirefoxUrlInfoInquirer.m" ascii //weight: 1
        $x_1_9 = "/FirefoxProfileManager.m" ascii //weight: 1
        $x_1_10 = "killall -9 blblu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


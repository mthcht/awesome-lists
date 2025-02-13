rule Trojan_MacOS_MacFileOpener_B_2147793718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MacFileOpener.B!MTB"
        threat_id = "2147793718"
        type = "Trojan"
        platform = "MacOS: "
        family = "MacFileOpener"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killMainApp" ascii //weight: 1
        $x_1_2 = "Library/Preferences/com.pcvark.Mac-File-Opener.plist" ascii //weight: 1
        $x_1_3 = "/Library/Caches/com.pcvark.Mac-File-Opener" ascii //weight: 1
        $x_1_4 = "trk.advancedmaccleaner.com/trackerwcfsrv/tracker.svc/trackOffersAccepted/?q=pxl=%@" ascii //weight: 1
        $x_1_5 = "/Library/Logs/Mac File Opener.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


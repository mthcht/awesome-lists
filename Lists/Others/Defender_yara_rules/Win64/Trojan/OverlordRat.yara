rule Trojan_Win64_OverlordRat_CAT_2147975793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRat.CAT!MTB"
        threat_id = "2147975793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "overlord-client" ascii //weight: 5
        $x_5_2 = "readClipboardText" ascii //weight: 5
        $x_5_3 = "CheckInstalledBrowsers" ascii //weight: 5
        $x_5_4 = "CaptureAndSend" ascii //weight: 5
        $x_5_5 = "keylogger.go" ascii //weight: 5
        $x_5_6 = "persistence.go" ascii //weight: 5
        $x_5_7 = "screenshot.go" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


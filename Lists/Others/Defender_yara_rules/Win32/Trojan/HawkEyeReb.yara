rule Trojan_Win32_HawkEyeReb_A_2147751790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HawkEyeReb.A!!HawkEyeReb.gen!MTB"
        threat_id = "2147751790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HawkEyeReb"
        severity = "Critical"
        info = "HawkEyeReb: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HawkEye RebornX" ascii //weight: 1
        $x_1_2 = "_ScreenshotLogger" ascii //weight: 1
        $x_1_3 = "_KeyStrokeLogger" ascii //weight: 1
        $x_1_4 = "Webcam" ascii //weight: 1
        $x_1_5 = "processhacker" ascii //weight: 1
        $x_1_6 = "process explorer" ascii //weight: 1
        $x_1_7 = "\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_8 = "UseOperaPasswordFile" ascii //weight: 1
        $x_1_9 = "LoadPasswordsYandex" ascii //weight: 1
        $x_1_10 = "UseFirefoxProfileFolder" ascii //weight: 1
        $x_1_11 = "UseChromeProfileFolder" ascii //weight: 1
        $x_1_12 = "com.apple.WebKit2WebProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}


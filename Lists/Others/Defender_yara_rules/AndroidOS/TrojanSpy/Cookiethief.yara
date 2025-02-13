rule TrojanSpy_AndroidOS_Cookiethief_A_2147751588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cookiethief.A!MTB"
        threat_id = "2147751588"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cookiethief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "youzicheng.net/api/resource/uploadFacebookCookie" ascii //weight: 2
        $x_1_2 = "/data/data/com.facebook.katana/app_webview/Cookies" ascii //weight: 1
        $x_1_3 = "/files/CookiesChrome" ascii //weight: 1
        $x_1_4 = "cp %s /data/data/%s/files/%s" ascii //weight: 1
        $x_1_5 = "iconHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


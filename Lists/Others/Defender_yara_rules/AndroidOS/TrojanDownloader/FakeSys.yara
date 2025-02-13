rule TrojanDownloader_AndroidOS_FakeSys_A_2147789238_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/FakeSys.A!MTB"
        threat_id = "2147789238"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "FakeSys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hs_call_phone" ascii //weight: 1
        $x_1_2 = "dn_bottom_sms" ascii //weight: 1
        $x_1_3 = "wap.ylxdtww.com" ascii //weight: 1
        $x_1_4 = "kt/list.html" ascii //weight: 1
        $x_1_5 = "upload_deviceInfo" ascii //weight: 1
        $x_1_6 = "downloadAnZhiApk" ascii //weight: 1
        $x_1_7 = "click_monitor_url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


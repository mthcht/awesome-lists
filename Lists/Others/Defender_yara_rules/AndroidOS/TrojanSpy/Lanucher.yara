rule TrojanSpy_AndroidOS_Lanucher_A_2147643988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Lanucher.A"
        threat_id = "2147643988"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Lanucher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "block the sms beacuse it contain the temp block num" ascii //weight: 1
        $x_1_2 = "VEDIO_DOWNLOAD_FILE_PATH" ascii //weight: 1
        $x_1_3 = "BgService.java" ascii //weight: 1
        $x_1_4 = "VedioWebViewActivity" ascii //weight: 1
        $x_1_5 = "vedio_download_link" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


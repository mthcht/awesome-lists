rule TrojanDownloader_AndroidOS_Andup_A_2147759243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Andup.A!MTB"
        threat_id = "2147759243"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Andup"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.ee.com/1.apk" ascii //weight: 1
        $x_1_2 = "syscore.intent.action.DOWNLOAD_HIDE" ascii //weight: 1
        $x_1_3 = "startDownload4Ad" ascii //weight: 1
        $x_1_4 = "killProcess" ascii //weight: 1
        $x_1_5 = "kill_self" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


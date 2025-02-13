rule TrojanDownloader_AndroidOS_DownSMS_A_2147658649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/DownSMS.A"
        threat_id = "2147658649"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "DownSMS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f ?? ?? ?? ?? ?? ?? ?? ?? 2f 73 72 76 2e 74 78 74}  //weight: 2, accuracy: Low
        $x_1_2 = "activator.apk" ascii //weight: 1
        $x_1_3 = "val$wallpaperManager" ascii //weight: 1
        $x_1_4 = "/download/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


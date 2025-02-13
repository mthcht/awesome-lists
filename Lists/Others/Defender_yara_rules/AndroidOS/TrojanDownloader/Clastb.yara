rule TrojanDownloader_AndroidOS_Clastb_A_2147782932_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Clastb.A"
        threat_id = "2147782932"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Clastb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LoaderService$start$1" ascii //weight: 1
        $x_1_2 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 43 6f 6d 70 61 74 2e 42 75 69 6c 64 [0-16] 0a 20 20 20 20 20 20 20 20 20 20 20 [0-16] 2e 62 75 69 6c 64 28 29}  //weight: 1, accuracy: Low
        $x_1_3 = "installApp: " ascii //weight: 1
        $x_1_4 = "android.intent.extra.NOT_UNKNOWN_SOURCE" ascii //weight: 1
        $x_1_5 = "stopForeground" ascii //weight: 1
        $x_1_6 = "getExternalFilesDir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


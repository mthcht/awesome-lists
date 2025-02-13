rule TrojanDownloader_MacOS_X_Keydnap_A_2147717262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS_X/Keydnap.A"
        threat_id = "2147717262"
        type = "TrojanDownloader"
        platform = "MacOS_X: "
        family = "Keydnap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killall Terminal" ascii //weight: 1
        $x_1_2 = "/tmp/com.apple.icloudsyncd" ascii //weight: 1
        $x_1_3 = "lovefromscratch.ca/wp-admin/CVdetails.doc" ascii //weight: 1
        $x_1_4 = "TW9zdCBDb21tb24gSW50ZXJ2aWV3IFF" ascii //weight: 1
        $x_1_5 = "aHR0cDovL3d3dy5udWdnZXRzNDExLmNvbS9pY2xvdWRzeW5jZA==" ascii //weight: 1
        $x_1_6 = "T3ZlciB0aGUgd2Vla2VuZCwgdGhlIGZpcnN0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


rule TrojanDownloader_MacOS_Keydnap_B_2147745538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Keydnap.B!MTB"
        threat_id = "2147745538"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Keydnap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/tmp/com.apple.icloudsyncd" ascii //weight: 2
        $x_1_2 = "killall Terminal" ascii //weight: 1
        $x_1_3 = "elitefuck" ascii //weight: 1
        $x_1_4 = "_createDaemon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


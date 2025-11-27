rule TrojanDownloader_MacOS_Agent_AMTB_2147958362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Agent!AMTB"
        threat_id = "2147958362"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5190ef1733183a0dc63fb623357f56d6" ascii //weight: 1
        $x_3_2 = "https://%@/dynamic" ascii //weight: 3
        $x_3_3 = "/tmp/test.scpt" ascii //weight: 3
        $x_1_4 = "/tmp/osalogging.zip" ascii //weight: 1
        $x_1_5 = "https://%@/gate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


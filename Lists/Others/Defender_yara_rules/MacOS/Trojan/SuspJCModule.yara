rule Trojan_MacOS_SuspJCModule_AP_2147919177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspJCModule.AP"
        threat_id = "2147919177"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspJCModule"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.docker.sock" ascii //weight: 2
        $x_2_2 = "XorLogger" ascii //weight: 2
        $x_2_3 = "C2CommsLoop" ascii //weight: 2
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "UploadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


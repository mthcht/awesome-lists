rule Trojan_MacOS_SuspOsaDownload_A_2147958584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspOsaDownload.A"
        threat_id = "2147958584"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspOsaDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://%@/dynamic?txd=%@" ascii //weight: 2
        $x_2_2 = "Downloaded AppleScript source:" ascii //weight: 2
        $x_1_3 = "api-key" ascii //weight: 1
        $x_1_4 = "/tmp/test.scpt" ascii //weight: 1
        $x_1_5 = "https://%@/gate" ascii //weight: 1
        $x_1_6 = "----WebKitFormBoundary7MA4YWxkTrZu0gW" ascii //weight: 1
        $x_1_7 = "/tmp/osalogging.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


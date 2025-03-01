rule Trojan_MacOS_RustBucket_X_2147918953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/RustBucket.X"
        threat_id = "2147918953"
        type = "Trojan"
        platform = "MacOS: "
        family = "RustBucket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/Users/Shared/.pld" ascii //weight: 3
        $x_1_2 = "pid,user,ppid,start,comm" ascii //weight: 1
        $x_1_3 = "kern.boottime" ascii //weight: 1
        $x_1_4 = "/var/log/install.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_RustBucket_AY_2147918961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/RustBucket.AY"
        threat_id = "2147918961"
        type = "Trojan"
        platform = "MacOS: "
        family = "RustBucket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (compatible; msie 8.0; windows nt 6.1; trident/4.0)" ascii //weight: 1
        $x_1_2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)" ascii //weight: 1
        $x_3_3 = "com.apple.systemupdate.plist" ascii //weight: 3
        $x_2_4 = "/Library/Metadata/System Update" ascii //weight: 2
        $x_3_5 = "com.apple.safariupdate.plist" ascii //weight: 3
        $x_2_6 = "Library/Application Support/Safari Update" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


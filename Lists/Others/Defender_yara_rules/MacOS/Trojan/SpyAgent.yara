rule Trojan_MacOS_SpyAgent_B_2147829050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SpyAgent.B"
        threat_id = "2147829050"
        type = "Trojan"
        platform = "MacOS: "
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 f8 40 30 3c 32 8d 44 07 1f 48 89 c7 49 0f af f9 48 c1 ef 27 69 ff fb 00 00 00 29 f8 48 ff c6 41 89 c0 48 39 f1 75 d6}  //weight: 1, accuracy: High
        $x_1_2 = "launchctl stop com.apple.tccd" ascii //weight: 1
        $x_1_3 = "csrutil status | grep disabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


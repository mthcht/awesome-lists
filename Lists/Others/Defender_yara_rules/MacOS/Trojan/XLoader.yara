rule Trojan_MacOS_XLoader_B_2147888470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XLoader.B!MTB"
        threat_id = "2147888470"
        type = "Trojan"
        platform = "MacOS: "
        family = "XLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 0f 44 f2 4c 8d 04 36 4d 89 c1 49 81 f1 b7 1d c1 04 f7 c6 00 00 00 80 4d 0f 44 c8 4b 8d 34 09 49 89 f0 49 81 f0 b7 1d c1 04 41 f7 c1 00 00 00 80 4c 0f 44 c6 4b 8d 34 00 49 89 f1 49 81 f1 b7 1d c1 04 41 f7 c0 00 00 00 80 4c 0f 44 ce 4b 8d 34 09 49 89 f0 49 81 f0 b7 1d c1 04 41 f7 c1 00 00 00 80 4c 0f 44 c6 4b 8d 34 00 49 89 f1 49 81 f1 b7 1d c1 04 41 f7 c0 00 00 00 80 4c 0f 44 ce 4b 8d 34 09 49 89 f0 49 81 f0 b7 1d c1 04 41 f7 c1 00 00 00 80 4c 0f 44 c6 4b 8d 34 00 49 89 f1 49 81 f1 b7 1d c1 04 41 f7 c0 00 00 00 80 4c 0f 44 ce 4c 89 0f 48 81 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


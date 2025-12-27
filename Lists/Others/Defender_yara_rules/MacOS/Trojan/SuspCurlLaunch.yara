rule Trojan_MacOS_SuspCurlLaunch_A_2147959559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspCurlLaunch.A"
        threat_id = "2147959559"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspCurlLaunch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {63 00 75 00 72 00 6c 00 20 00 2d 00 6b 00 20 00 2d 00 73 00 20 00 2d 00 2d 00 6d 00 61 00 78 00 2d 00 74 00 69 00 6d 00 65 00 20 00 [0-6] 20 00 2d 00 2d 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 2d 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 [0-18] 55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00}  //weight: 3, accuracy: Low
        $x_3_2 = "api-key: " wide //weight: 3
        $x_3_3 = {68 00 74 00 74 00 70 00 [0-64] 2f 00 64 00 79 00 6e 00 61 00 6d 00 69 00 63 00 3f 00 74 00 78 00 64 00 3d 00}  //weight: 3, accuracy: Low
        $x_3_4 = "-o /dev/null -w" wide //weight: 3
        $x_3_5 = "http_code" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Linux_Stiniter_A_2147655367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Stiniter.A"
        threat_id = "2147655367"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Stiniter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/data/log.txt" ascii //weight: 1
        $x_1_2 = "/data/rend" ascii //weight: 1
        $x_1_3 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 00 00 2f 00 00 00 70 69 70 65 43 6d 64 3a 3c 25 73 3e}  //weight: 1, accuracy: High
        $x_1_4 = "/system/bin/keeper" ascii //weight: 1
        $x_1_5 = "read fd isset" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Stiniter_A_2147655367_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Stiniter.A"
        threat_id = "2147655367"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Stiniter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/googlemessage.apk" ascii //weight: 1
        $x_1_2 = "/android.info" ascii //weight: 1
        $x_1_3 = "/system/bin/android.info" ascii //weight: 1
        $x_1_4 = "/system/bin/keeper" ascii //weight: 1
        $x_1_5 = "/system/bin/ts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Stiniter_A_2147655367_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Stiniter.A"
        threat_id = "2147655367"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Stiniter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data/com.google.updateservice/sys.info" ascii //weight: 1
        $x_1_2 = {63 68 6d 6f 64 20 30 37 37 37 20 2f 73 79 73 74 65 6d 2f 65 74 63 00 00 2f 64 61 74 61 2f 67 6f 6f 67 6c 65 73 65 72 76 69 63 65 2e 61 70 6b 00 70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72}  //weight: 1, accuracy: High
        $x_1_3 = "Download_url_list" ascii //weight: 1
        $x_1_4 = "/HeartBeat.do" ascii //weight: 1
        $x_1_5 = "tgloader-android" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


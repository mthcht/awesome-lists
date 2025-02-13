rule Trojan_AndroidOS_Smammer_A_2147654199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smammer.A"
        threat_id = "2147654199"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smammer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 67 00 0c 62 6c 61 63 6b 4e 75 6d 62 65 72 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "downloader/SmsReceiver$Scan" ascii //weight: 1
        $x_1_3 = "downloader/AppDownloaderActivity" ascii //weight: 1
        $x_1_4 = {41 70 70 44 6f 77 6e 6c 6f 61 64 65 72 41 63 74 69 76 69 74 79 2e 6a 61 76 61 00 0b 43 6f 6e 66 69 67 2e 6a 61 76 61}  //weight: 1, accuracy: High
        $x_1_5 = {e2 80 a1 d0 b0 d0 b3 d1 80 d1 83 d0 b7 d0 ba d0 b0 20 00 01 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


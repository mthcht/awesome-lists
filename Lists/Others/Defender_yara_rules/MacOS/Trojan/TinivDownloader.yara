rule Trojan_MacOS_TinivDownloader_A_2147750544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/TinivDownloader.A!MTB"
        threat_id = "2147750544"
        type = "Trojan"
        platform = "MacOS: "
        family = "TinivDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 00 00 90 08 61 2d 91 29 00 00 90 29 61 33 91 a0 83 1f f8 a1 03 1f f8 a2 f3 1e 38 29 01 40 f9 01 01 40 f9 e0 03 09 aa df 08 00 94 28 00 00 90 08 81 0a 91 09 00 80 d2 21 00 00 90 21 80 2d 91 21 00 40 f9 e2 03 08 aa e3 03 09 aa d6 08 00 94 28 00 00 90 08 a1 2d 91 29 00 00 90 29 81 33 91 a0 03 1e f8 29 01 40 f9 a2 03 5e f8 01 01 40 f9 e0 03 09 aa cc 08 00 94 28 00 00 90 08 01 0b 91}  //weight: 1, accuracy: High
        $x_1_2 = "YKA4SGYAN7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_TinivDownloader_E_2147755768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/TinivDownloader.E!MTB"
        threat_id = "2147755768"
        type = "Trojan"
        platform = "MacOS: "
        family = "TinivDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iphoneos/zheng.build" ascii //weight: 1
        $x_1_2 = "api.6ta.co/killm.php" ascii //weight: 1
        $x_1_3 = "5RN3WMLSLE" ascii //weight: 1
        $x_1_4 = "B67LTLAN5S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


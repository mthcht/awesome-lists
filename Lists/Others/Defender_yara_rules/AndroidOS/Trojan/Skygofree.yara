rule Trojan_AndroidOS_Skygofree_2147725385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Skygofree"
        threat_id = "2147725385"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Skygofree"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f0 b5 15 1c 4e 4e 0a 1c 6a 43 85 b0 7e 44 03 91 1c 1c 01 92 00 2a 01 d1 00 25 8e e0}  //weight: 1, accuracy: High
        $x_1_2 = "/system/bin/sh -c" ascii //weight: 1
        $x_1_3 = "chmod -R 777 /data/data/com.whatsapp" ascii //weight: 1
        $x_1_4 = {f0 b5 2d 4a 2d 4f 8b b0 7a 44 01 92 03 aa 7f 44 11 1c 70 cf 70 c1 3b 68 ?? 24 0b 60 ?? 28 48 d0 ?? 24 ?? 60 60 02 09 ?? 09 a9 08 aa 00 20 0a f0 ?? ?? 0a f0 ?? ?? 04 1c 42 1c 02 d0 00 28 06 d0 16 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Skygofree_A_2147809144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Skygofree.A!MTB"
        threat_id = "2147809144"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Skygofree"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendPhoneContacts" ascii //weight: 1
        $x_1_2 = "upload_sms.php" ascii //weight: 1
        $x_1_3 = "SendFileSystemList" ascii //weight: 1
        $x_1_4 = "upload_info_tel.php" ascii //weight: 1
        $x_1_5 = "getInstalledApps" ascii //weight: 1
        $x_1_6 = "EXPLOIT SUCCESS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


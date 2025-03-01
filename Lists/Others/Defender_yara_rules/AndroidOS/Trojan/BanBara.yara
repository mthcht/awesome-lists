rule Trojan_AndroidOS_BanBara_D_2147837276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BanBara.D"
        threat_id = "2147837276"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BanBara"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wait4serviceMessenger" ascii //weight: 1
        $x_1_2 = "com.orchestra.watchdog.C2C" ascii //weight: 1
        $x_1_3 = "HEADER_AES_KEY" ascii //weight: 1
        $x_1_4 = "rsaEncoder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BanBara_A_2147840489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BanBara.A!MTB"
        threat_id = "2147840489"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BanBara"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.orchestra.watchdog.C2C" ascii //weight: 1
        $x_1_2 = "wait4serviceMessenger" ascii //weight: 1
        $x_1_3 = {35 14 12 00 34 25 03 00 12 05 48 06 09 04 48 07 0a 05 b7 76 8d 66 4f 06 09 04 d8 04 04 01 d8 05 05 01 28 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


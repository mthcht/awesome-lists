rule Trojan_MSIL_ZhongStealer_AMTB_2147964709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZhongStealer!AMTB"
        threat_id = "2147964709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZhongStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {20 88 81 e8 74 06 61 07 58 0c 11 04 08 1f 10 63 d1 28 28 00 00 0a 08 d1 28 28 00 00 0a 26 20 81 bf f0 eb 06 59 07 59 0c 11 04 08 1f 10 63 d1 28 28 00 00 0a 08 d1 28 28 00 00 0a 26 06 20 9d 81 ef 74 61 07 58 0c 11 04 08 d1 28 28 00 00 0a 08 1f 10 63 d1 28 28 00 00 0a 26 06 20 73 22 24 87 58 07 61 0c 11 04 08 1f 10 63 d1 28 28 00 00 0a 08 d1 28 28 00 00 0a 26 06 20 97 81 ef 74 61 07 58 0c 11 04 08 1f 10 63 d1 28 28 00 00 0a 08 d1 28 28 00 00 0a 26 06 20 6a 22 16 87 58 07 61 0c 11 04 08 1f 10 63}  //weight: 7, accuracy: High
        $x_1_2 = "set_UseShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZhongStealer_A_2147964710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZhongStealer.A!AMTB"
        threat_id = "2147964710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZhongStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {11 19 11 12 14 fe 03 33 0d 7e 07 00 00 04 1f 20 61 80 07 00 00 04 7e 07 00 00 04 20 f6 f1 f8 39 06 61 07 59 17 11 07 58 60 61 80 07 00 00 04}  //weight: 7, accuracy: High
        $x_1_2 = "set_UseShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Retliften_A_2147782827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Retliften.A"
        threat_id = "2147782827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Retliften"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 6e 65 74 66 69 6c 74 65 72 64 72 76 2e 70 64 62 00}  //weight: 10, accuracy: High
        $x_5_2 = "http://110.42.4.180:" ascii //weight: 5
        $x_6_3 = "atsv2,.817(<1/=.6>89" ascii //weight: 6
        $x_3_4 = {45 8a 01 45 84 c0 74 31 b8 ?? ?? ?? ?? 41 8b ca 41 f7 e2 41 8b c2 41 ff c2 2b c2 d1 e8 03 c2 c1 e8 02 6b c0 07 2b c8 48 63 c1 44 32 04 83 45 88 01 49 ff c1 45 3b d3 7c c7}  //weight: 3, accuracy: Low
        $x_3_5 = {8a 1c 31 84 db 74 2f b8 25 49 92 24 f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 02 8d 14 c5 00 00 00 00 2b d0 8b c1 2b c2 8b 55 10 8a 04 82 32 c3 88 04 31 41 3b cf 7c ca}  //weight: 3, accuracy: High
        $x_1_6 = "U?8Zffuoikrmq" wide //weight: 1
        $x_1_7 = "HusiKlooi`SZO" wide //weight: 1
        $x_1_8 = ")HSRX,0'1??@lr}:'" ascii //weight: 1
        $x_1_9 = "lxwjgqd{.b~m" ascii //weight: 1
        $x_2_10 = "\\??\\netfilter" wide //weight: 2
        $x_2_11 = "AutoConfigURL" wide //weight: 2
        $x_1_12 = "EnableLegacyAutoProxyFeatures" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}


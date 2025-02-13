rule Trojan_MacOS_Mystikal_A_2147890089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Mystikal.A"
        threat_id = "2147890089"
        type = "Trojan"
        platform = "MacOS: "
        family = "Mystikal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YXBmZWxsLmlkICsgSlNPTi5zdHJpbmdpZnk" ascii //weight: 3
        $x_3_2 = "aWYoYXBmZWxsLmlkID09PSB1bmRlZmluZWQgfHwgYXBmZWxsLmlkID09PSAiIi" ascii //weight: 3
        $x_2_3 = "JCh7InR5cGUiOiAkKCI0MiIpLCAiYnNpeiI6IDQwOTYsICJwZXJtIjogZmFsc2V9KTs" ascii //weight: 2
        $x_1_4 = "plugin.cpp" ascii //weight: 1
        $x_1_5 = "!returnVal" ascii //weight: 1
        $x_1_6 = "_OBJC_CLASS_$_OSAScript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


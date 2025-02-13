rule Trojan_AndroidOS_Oscorp_B_2147794677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Oscorp.B"
        threat_id = "2147794677"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Oscorp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mapwqpdox201q/xl0562013zpeetypwqq/MmsRe" ascii //weight: 1
        $x_1_2 = "/oeeq0457502wps951/Lukas" ascii //weight: 1
        $x_1_3 = "Still decompiling , my nigga?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Oscorp_A_2147797061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Oscorp.A"
        threat_id = "2147797061"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Oscorp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HIDDENfirstTime" ascii //weight: 1
        $x_1_2 = "fuck" ascii //weight: 1
        $x_1_3 = "com.cosmos.starwarz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


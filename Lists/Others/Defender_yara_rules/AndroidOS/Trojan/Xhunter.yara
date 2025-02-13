rule Trojan_AndroidOS_Xhunter_A_2147838967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Xhunter.A"
        threat_id = "2147838967"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Xhunter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.xhunter.client" ascii //weight: 2
        $x_2_2 = "<++++++++++++++++><><>><<<<>Successfully started myself++++>>>>>>>>" ascii //weight: 2
        $x_2_3 = "xhunterTest" ascii //weight: 2
        $x_2_4 = "{\"text\":\"Victim " ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


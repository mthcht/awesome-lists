rule Trojan_AndroidOS_Monokle_A_2147783374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Monokle.A"
        threat_id = "2147783374"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Monokle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "recs233268" ascii //weight: 1
        $x_1_2 = "nsr39562267.lmt" ascii //weight: 1
        $x_1_3 = "Android/data/serv8202965" ascii //weight: 1
        $x_1_4 = "lcd110992264.d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


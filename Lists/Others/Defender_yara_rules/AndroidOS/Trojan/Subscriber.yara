rule Trojan_AndroidOS_Subscriber_A_2147849505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Subscriber.A"
        threat_id = "2147849505"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Subscriber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tihipmachinenic" ascii //weight: 2
        $x_2_2 = "latolympicbenchproxy" ascii //weight: 2
        $x_2_3 = "seatedrowmachinreporter" ascii //weight: 2
        $x_2_4 = "ighadductormachsequence" ascii //weight: 2
        $x_2_5 = "norhipabductorubuffer" ascii //weight: 2
        $x_2_6 = "flatbenchenterl" ascii //weight: 2
        $x_2_7 = "soft_reversecir" ascii //weight: 2
        $x_2_8 = "arent_legcurlma" ascii //weight: 2
        $x_2_9 = "all_cablecrossn" ascii //weight: 2
        $x_2_10 = "taryTorsoMachin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Subscriber_C_2147852274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Subscriber.C"
        threat_id = "2147852274"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Subscriber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ustablebench_pa" ascii //weight: 1
        $x_1_2 = "onNotificationRemoved  1111111111" ascii //weight: 1
        $x_1_3 = "takeofffoot_cor" ascii //weight: 1
        $x_1_4 = "shoComIwr" ascii //weight: 1
        $x_1_5 = "tilitybench_hav" ascii //weight: 1
        $x_1_6 = "ter_seatedlegcu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


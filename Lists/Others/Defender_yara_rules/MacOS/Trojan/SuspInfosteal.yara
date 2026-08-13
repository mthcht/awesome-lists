rule Trojan_MacOS_SuspInfosteal_A_2147976086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspInfosteal.A"
        threat_id = "2147976086"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspInfosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "reserve_botnet_start" ascii //weight: 2
        $x_1_2 = "chrome_masterpass" ascii //weight: 1
        $x_1_3 = "grab_folder" ascii //weight: 1
        $x_1_4 = "telegram" ascii //weight: 1
        $x_1_5 = "grab_plugins" ascii //weight: 1
        $x_1_6 = "swap_app" ascii //weight: 1
        $x_1_7 = "tnet_init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


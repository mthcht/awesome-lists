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

rule Trojan_MacOS_SuspInfosteal_B_2147978647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspInfosteal.B"
        threat_id = "2147978647"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspInfosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 65 63 75 72 69 74 79 00 75 6e 6c 6f 63 6b 2d 6b 65 79 63 68 61 69 6e 00 2d 70}  //weight: 1, accuracy: High
        $x_1_2 = "set-generic-password-partition-list" ascii //weight: 1
        $x_1_3 = "SONOMA_AGENT" ascii //weight: 1
        $x_1_4 = {70 6b 69 6c 6c 20 [0-16] 27 47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65 20 48 65 6c 70 65 72}  //weight: 1, accuracy: Low
        $x_1_5 = "sysctl -n kern.boottime 2>/dev/null" ascii //weight: 1
        $x_1_6 = "-c -k --sequesterRsrc" ascii //weight: 1
        $x_1_7 = "decoy.downloaded_today" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


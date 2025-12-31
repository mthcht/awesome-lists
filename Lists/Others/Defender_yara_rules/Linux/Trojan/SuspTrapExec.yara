rule Trojan_Linux_SuspTrapExec_MP14_2147960310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspTrapExec.MP14"
        threat_id = "2147960310"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspTrapExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "trap " wide //weight: 10
        $x_10_2 = "nohup " wide //weight: 10
        $x_10_3 = "sh " wide //weight: 10
        $x_10_4 = " EXIT" wide //weight: 10
        $n_100_5 = "echo $? " wide //weight: -100
        $n_100_6 = "/exit_code" wide //weight: -100
        $n_100_7 = "/output.log" wide //weight: -100
        $n_100_8 = "/error.log" wide //weight: -100
        $n_100_9 = "DigitalOcean" wide //weight: -100
        $n_100_10 = "snapshooter" wide //weight: -100
        $n_100_11 = "strap" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


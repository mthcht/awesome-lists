rule Trojan_Linux_Sysrv_GA_2147815712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sysrv.GA"
        threat_id = "2147815712"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sysrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exp.Attack" ascii //weight: 1
        $x_1_2 = "/exp.go" ascii //weight: 1
        $n_1_3 = "/math/rand/exp.go" ascii //weight: -1
        $x_1_4 = "/zmap/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}


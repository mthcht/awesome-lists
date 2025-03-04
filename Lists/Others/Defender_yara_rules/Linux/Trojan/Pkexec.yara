rule Trojan_Linux_Pkexec_A_2147811491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Pkexec.A"
        threat_id = "2147811491"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Pkexec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "gconv_path=" wide //weight: 10
        $n_10_2 = "dgconv_path=" wide //weight: -10
        $n_10_3 = "data/yocto/key-coms-apps" wide //weight: -10
        $n_10_4 = "kirkstone-bsp/build_mgea" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


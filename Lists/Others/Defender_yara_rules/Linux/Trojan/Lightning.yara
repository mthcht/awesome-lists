rule Trojan_Linux_Lightning_A_2147828714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Lightning.A"
        threat_id = "2147828714"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Lightning"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/usr/lib64/seahorses/" ascii //weight: 1
        $x_1_2 = {4c 69 67 68 74 6e 69 6e 67 2e (43 6f|44 6f 77 6e 6c 6f 61 64)}  //weight: 1, accuracy: Low
        $x_1_3 = "kkdmflush" ascii //weight: 1
        $x_1_4 = "proc/y.y" ascii //weight: 1
        $x_1_5 = "Linux.Plugin.Lightning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


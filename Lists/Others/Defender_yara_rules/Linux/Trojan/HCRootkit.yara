rule Trojan_Linux_HCRootkit_A_2147794501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/HCRootkit.A"
        threat_id = "2147794501"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "HCRootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sbin/insmod %s > /dev/null 2>&1" ascii //weight: 1
        $x_1_2 = "/bin/dmesg -c > /dev/null 2>&1" ascii //weight: 1
        $x_1_3 = "/proc/.inl" ascii //weight: 1
        $x_1_4 = "/tmp/.tmp_XXXXXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_HCRootkit_B_2147794502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/HCRootkit.B"
        threat_id = "2147794502"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "HCRootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hide_proc" ascii //weight: 1
        $x_1_2 = "s_hide_pids" ascii //weight: 1
        $x_1_3 = "s_inl_entry" ascii //weight: 1
        $x_1_4 = "rootkit" ascii //weight: 1
        $x_1_5 = "s_hide_tcp4_ports" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


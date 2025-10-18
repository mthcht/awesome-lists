rule Trojan_Linux_LinkPro_A_2147955462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LinkPro.A"
        threat_id = "2147955462"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LinkPro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "link-pro/link-client" ascii //weight: 1
        $x_1_2 = "resources/libld.so" ascii //weight: 1
        $x_1_3 = "resources/arp_diag.ko" ascii //weight: 1
        $x_1_4 = "hidePrograms" ascii //weight: 1
        $x_1_5 = "knock_prog" ascii //weight: 1
        $x_1_6 = "creack/pty" ascii //weight: 1
        $x_1_7 = "resocks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_LinkPro_B_2147955463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LinkPro.B"
        threat_id = "2147955463"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LinkPro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getdents" ascii //weight: 1
        $x_1_2 = "readdir" ascii //weight: 1
        $x_1_3 = ".tmp~data" ascii //weight: 1
        $x_1_4 = "/proc/net" ascii //weight: 1
        $x_1_5 = ".system" ascii //weight: 1
        $x_1_6 = "sshids" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_LinkPro_C_2147955464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LinkPro.C"
        threat_id = "2147955464"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LinkPro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hook_udp6_seq_show" ascii //weight: 1
        $x_1_2 = "hook_udp4_seq_show" ascii //weight: 1
        $x_1_3 = "hook_tcp6_seq_show" ascii //weight: 1
        $x_1_4 = "hook_tcp4_seq_show" ascii //weight: 1
        $x_1_5 = "ftrace_thunk" ascii //weight: 1
        $x_1_6 = "hide_port_init" ascii //weight: 1
        $x_1_7 = "hide_port_exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Linux_LinkPro_D_2147955465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LinkPro.D"
        threat_id = "2147955465"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LinkPro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/syscalls/sys_enter_getdents" ascii //weight: 1
        $x_1_2 = "/syscalls/sys_exit_getdents" ascii //weight: 1
        $x_1_3 = "/syscalls/sys_enter_bpf" ascii //weight: 1
        $x_1_4 = "BPF cmd: %d, start_id: %u" ascii //weight: 1
        $x_1_5 = "HIDING NEXT_ID: %u" ascii //weight: 1
        $x_1_6 = ".tmp~data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Linux_LinkPro_E_2147955466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LinkPro.E"
        threat_id = "2147955466"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LinkPro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[KNOCK-SET]" ascii //weight: 1
        $x_1_2 = "[KNOCK]" ascii //weight: 1
        $x_1_3 = "[DBG-XDP]" ascii //weight: 1
        $x_1_4 = "[DBG-KNOCK]" ascii //weight: 1
        $x_1_5 = "[TC-MISS]" ascii //weight: 1
        $x_1_6 = "[EXPIRED]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Linux_LinkPro_F_2147955467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LinkPro.F"
        threat_id = "2147955467"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LinkPro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/.del" ascii //weight: 1
        $x_1_2 = "expand 32-byte k" ascii //weight: 1
        $x_1_3 = "cosmanking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


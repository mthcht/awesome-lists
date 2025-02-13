rule Backdoor_Linux_Winnti_A_2147735867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Winnti.A!dha"
        threat_id = "2147735867"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[advNetSrv] can not create a PF_INET socket" ascii //weight: 1
        $x_1_2 = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null" ascii //weight: 1
        $x_1_3 = "CONNECT %s:%d HTTP/1.0" ascii //weight: 1
        $x_1_4 = "HIDE_THIS_SHELL=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Winnti_B_2147735868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Winnti.B!dha"
        threat_id = "2147735868"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_our_sockets" ascii //weight: 1
        $x_1_2 = "is_invisible_with_pids" ascii //weight: 1
        $x_1_3 = "/usr/bin/netstat" ascii //weight: 1
        $x_1_4 = "socket:[%d]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


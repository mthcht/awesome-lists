rule Trojan_Linux_Turla_A_2147772779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Turla.A!MTB"
        threat_id = "2147772779"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/.sync.pid" ascii //weight: 1
        $x_1_2 = "/root/.session" ascii //weight: 1
        $x_1_3 = "/root/.hsperfdata" ascii //weight: 1
        $x_1_4 = "File already exist on remote filesystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Turla_HA_2147833803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Turla.HA"
        threat_id = "2147833803"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/root/.sess" ascii //weight: 2
        $x_2_2 = "/root/.tmpware" ascii //weight: 2
        $x_2_3 = "/root/.hsperfdata" ascii //weight: 2
        $x_2_4 = "/root/.xfdshp1" ascii //weight: 2
        $x_2_5 = "/tmp/.sync.pid" ascii //weight: 2
        $x_2_6 = "/tmp/.xdfg" ascii //weight: 2
        $x_1_7 = "TREX_PID=%u" ascii //weight: 1
        $x_1_8 = "Remote VS is empty !" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Turla_XO_2147836689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Turla.XO"
        threat_id = "2147836689"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 ea 03 83 e7 07 c1 e2 0d ?? ?? ?? ?? ?? 8d 41 05 32 06 48 ff c6 88 81 ?? ?? ?? ?? 48 ff c1 48 83 f9 49 75 e9}  //weight: 10, accuracy: Low
        $x_10_2 = {53 48 8d 82 74 38 00 00 4c 8d 82 6c 38 00 00 89 fb 48 89 f7 48 83 ec 10 85 c9 48 8d 8a 24 28 00 00 4c 8d 4c 24 0c 4c 0f 45 c0 48 63 d3 c7 44 24 0c 00 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Turla_B_2147849465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Turla.B"
        threat_id = "2147849465"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ERROR: Unlinking tmp WTMP file." ascii //weight: 1
        $x_1_2 = "USAGE: wipe [ u|w|l|a ] ...options..." ascii //weight: 1
        $x_1_3 = "Erase acct entries on tty : wipe a [username] [tty]" ascii //weight: 1
        $x_1_4 = "Alter lastlog entry : wipe l [username] [tty] [time] [host]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_Turla_C_2147849466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Turla.C"
        threat_id = "2147849466"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stack = 0x%x, targ_addr = 0x%x" ascii //weight: 1
        $x_1_2 = "execl failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Turla_D_2147849467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Turla.D"
        threat_id = "2147849467"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Log ended at => %s" ascii //weight: 1
        $x_1_2 = "Log started at => %s [pid %d]" ascii //weight: 1
        $x_1_3 = "/var/tmp/taskhost" ascii //weight: 1
        $x_1_4 = "my hostname: %s" ascii //weight: 1
        $x_1_5 = "/var/tmp/tasklog" ascii //weight: 1
        $x_1_6 = "/var/tmp/.Xtmp01" ascii //weight: 1
        $x_1_7 = "myfilename=-%s-" ascii //weight: 1
        $x_1_8 = "/var/tmp/taskpid" ascii //weight: 1
        $x_1_9 = "mypid=-%d-" ascii //weight: 1
        $x_1_10 = "/var/tmp/taskgid" ascii //weight: 1
        $x_1_11 = "mygid=-%d-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Linux_Turla_E_2147849468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Turla.E"
        threat_id = "2147849468"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "./a filename template_file" ascii //weight: 1
        $x_1_2 = "May be %s is empty?" ascii //weight: 1
        $x_1_3 = "template string = |%s|" ascii //weight: 1
        $x_1_4 = "No blocks !!!" ascii //weight: 1
        $x_1_5 = "No data in this block !!!!!!" ascii //weight: 1
        $x_1_6 = "No good line" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


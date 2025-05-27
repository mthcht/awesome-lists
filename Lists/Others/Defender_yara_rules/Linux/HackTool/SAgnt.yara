rule HackTool_Linux_SAgnt_B_2147825989_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SAgnt.B!xp"
        threat_id = "2147825989"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "modMESSAGES" ascii //weight: 1
        $x_1_2 = "the process time is %d ms" ascii //weight: 1
        $x_1_3 = "modSECURE" ascii //weight: 1
        $x_1_4 = "modSYSLOG" ascii //weight: 1
        $x_1_5 = "cleaning logs file finished" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_Linux_SAgnt_A_2147826934_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SAgnt.A!xp"
        threat_id = "2147826934"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[*] syslogd killed" ascii //weight: 1
        $x_1_2 = "syslogd/newsyslogd attack" ascii //weight: 1
        $x_1_3 = "%s -i string -m /var/log/messages" ascii //weight: 1
        $x_1_4 = "warning is in PROMISC MODE" ascii //weight: 1
        $x_1_5 = "impossible restart syslogd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_Linux_SAgnt_B_2147838808_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SAgnt.B!MTB"
        threat_id = "2147838808"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 3f e8 26 99 77 71 56 05 11 6b 9b cf 1c b7 31 a7 bb dc 46 9c b1 12 f1 36 62 45 d6 6f 38 d7 33 c7 8f a8 42 dd 1d 2a 35 f4 89 0b 56 12 15 6d e8 ce ee 75 1b dd 2b 89 f2 36 0c 64 e9 b9 28 ae 03 e2 6a 5d 30 4e 4c aa 65 9e 6e 8e 1e dd}  //weight: 1, accuracy: High
        $x_1_2 = {6d 47 88 6a 0d ce e4 14 7a 29 36 1e ea 84 ce d6 38 a7 e1 6c 88 e9 bf fa 64 7d d3 a4 a4 2d b0 fa 58 32 99 9c 9c d4 df a6 d8 91 49 dd d5 f7 c9 e9 74 6c 72 2c 16 4b c6 92 4d b1 71 4d b1 c9 35 b1 d8 a4 f4 a4 d2 c7 24 15 b3 5b e3 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_SAgnt_C_2147898353_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SAgnt.C!MTB"
        threat_id = "2147898353"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "intercept_ssh_client" ascii //weight: 1
        $x_1_2 = "find_password_write" ascii //weight: 1
        $x_1_3 = "src/ssh_tracer.c" ascii //weight: 1
        $x_1_4 = "intercept_sudo" ascii //weight: 1
        $x_1_5 = "passwd_tracer.c" ascii //weight: 1
        $x_1_6 = "extract_read_string" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Linux_SAgnt_D_2147919062_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SAgnt.D!MTB"
        threat_id = "2147919062"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fetchOrgInfo" ascii //weight: 1
        $x_1_2 = "handleSSHLogin" ascii //weight: 1
        $x_1_3 = "main.sendTelegramMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_SAgnt_E_2147942306_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SAgnt.E!MTB"
        threat_id = "2147942306"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.(*connPool).addConn" ascii //weight: 1
        $x_1_2 = "main.newAntitrackLinkTask" ascii //weight: 1
        $x_1_3 = "main.(*antitrackLinkNet).addTaskConn" ascii //weight: 1
        $x_1_4 = "main.getIPv4Client" ascii //weight: 1
        $x_1_5 = "main.runAntitrackRouter" ascii //weight: 1
        $x_1_6 = "main.(*serverMsgDispatch).start" ascii //weight: 1
        $x_1_7 = "main.allowTunForward" ascii //weight: 1
        $x_1_8 = "main.addSnatRule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


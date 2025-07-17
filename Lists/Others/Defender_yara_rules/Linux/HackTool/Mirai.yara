rule HackTool_Linux_Mirai_2147765816_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Mirai.a!MTB"
        threat_id = "2147765816"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "High"
        info = "a: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TCP stomp flood" ascii //weight: 1
        $x_1_2 = "GRE Ethernet flood" ascii //weight: 1
        $x_1_3 = "main NewAttack " ascii //weight: 1
        $x_1_4 = "CanLaunchAttack" ascii //weight: 1
        $x_1_5 = "DDOS | Succesfully hijacked connection" ascii //weight: 1
        $x_1_6 = "DDOS | Masking connection from utmp+wtmp" ascii //weight: 1
        $x_2_7 = {6d 69 72 61 69 31 2f [0-21] 2f [0-16] 6d 69 72 61 69 [0-16] 2f [0-16] 2f 63 6e 63}  //weight: 2, accuracy: Low
        $x_1_8 = "Cannot specify more than 255 targets in a single attack!" ascii //weight: 1
        $x_1_9 = "runtime.injectglist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_Mirai_B_2147946604_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Mirai.B!MTB"
        threat_id = "2147946604"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.BuildKillSelf" ascii //weight: 1
        $x_1_2 = "/mirai/cnc/bot.go" ascii //weight: 1
        $x_1_3 = "main.AttackSend" ascii //weight: 1
        $x_1_4 = "main.encryptCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


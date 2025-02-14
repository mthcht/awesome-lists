rule HackTool_MacOS_Chisel_A_2147839848_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.A!MTB"
        threat_id = "2147839848"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/jpillora/chisel/" ascii //weight: 1
        $x_1_2 = "chiselclientclosedconfigcookie" ascii //weight: 1
        $x_1_3 = "main.generatePidFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Chisel_B_2147893467_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.B!MTB"
        threat_id = "2147893467"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHISEL_CONNECT" ascii //weight: 1
        $x_1_2 = "sendchisel" ascii //weight: 1
        $x_1_3 = "chisel.pid" ascii //weight: 1
        $x_1_4 = "chiselclientclosed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Chisel_C_2147921860_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.C!MTB"
        threat_id = "2147921860"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/jpillora/chisel/share/ccrypto.IsChiselKey" ascii //weight: 2
        $x_1_2 = "chisel/client" ascii //weight: 1
        $x_1_3 = "CHISEL_KEY_FILE" ascii //weight: 1
        $x_1_4 = "main.generatePidFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_MacOS_Chisel_E_2147923774_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.E!MTB"
        threat_id = "2147923774"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 38 48 89 d7 48 8b 05 a5 b0 56 00 48 8b 00 48 89 45 d0 ff 15 98 b1 56 00 49 89 c6 0f 28 05 7e 54 55 00 0f 29 45 b0 c7 45 c0 03 00 00 00 48 8b 35 44 4c 58 00 48 8d 15 7d cc 56 00 48 89 c7 ff 15 54 b1 56 00 84 c0}  //weight: 1, accuracy: High
        $x_1_2 = {45 0f b6 44 07 79 45 0f b6 4c 07 7a 45 0f b6 54 07 7b 45 0f b6 5c 07 7c 41 0f b6 5c 07 7d 48 8b 35 5e 4a 58 00 48 83 ec 08 48 8d 15 9b ce 56 00 4c 8b 2d 74 af 56 00 31 c0 53 41 53 41 52 41 ff d5 48 83 c4 20 48 89 c7 e8 e0 41 55 00 49 89 c4 4c 89 ff e8 d7 3f 55 00 48 8b 35 c4 4a 58 00 4c 89 e7 41 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Chisel_F_2147923944_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.F!MTB"
        threat_id = "2147923944"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chisel-v30." ascii //weight: 1
        $x_1_2 = "jpillora/chisel/share/tunnel" ascii //weight: 1
        $x_1_3 = "chisel/share/ccrypto.FingerprintKey" ascii //weight: 1
        $x_1_4 = "client.NewClient.Password.func1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_MacOS_Chisel_D_2147924460_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.D!MTB"
        threat_id = "2147924460"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.generatePidFile" ascii //weight: 1
        $x_1_2 = "chisel/server.NewServer" ascii //weight: 1
        $x_1_3 = "/chisel/client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Chisel_G_2147929992_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.G!MTB"
        threat_id = "2147929992"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tunnel_in_proxy.go" ascii //weight: 1
        $x_1_2 = "main.generatePidFile" ascii //weight: 1
        $x_1_3 = "/tunnel_out_ssh.go" ascii //weight: 1
        $x_1_4 = "server/server_listen.go" ascii //weight: 1
        $x_1_5 = "/jpillora/requestlog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Chisel_H_2147933405_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Chisel.H!MTB"
        threat_id = "2147933405"
        type = "HackTool"
        platform = "MacOS: "
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(*Tunnel).activatingConnWait" ascii //weight: 1
        $x_1_2 = "tunnel_in_proxy.go" ascii //weight: 1
        $x_1_3 = "(*waitGroup).DoneAll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


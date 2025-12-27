rule HackTool_Linux_ReverseSSH_A_2147888943_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ReverseSSH.A!MTB"
        threat_id = "2147888943"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ReverseSSH"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "reverse_ssh/cmd/client" ascii //weight: 5
        $x_5_2 = "syscall.bind" ascii //weight: 5
        $x_5_3 = "UserAgent" ascii //weight: 5
        $x_1_4 = "ForceAttemptHTTP2" ascii //weight: 1
        $x_1_5 = "http.fakeLocker" ascii //weight: 1
        $x_1_6 = "subsystems.setuid" ascii //weight: 1
        $x_1_7 = "maxIncomingPayload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_ReverseSSH_B_2147925838_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ReverseSSH.B!MTB"
        threat_id = "2147925838"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ReverseSSH"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NHAS/reverse_ssh/cmd/client/main.go" ascii //weight: 1
        $x_1_2 = "subsystems.setgid" ascii //weight: 1
        $x_1_3 = "client/handlers/subsystems/sftp.go" ascii //weight: 1
        $x_1_4 = "reverse_ssh/pkg/logger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_ReverseSSH_C_2147935674_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ReverseSSH.C!MTB"
        threat_id = "2147935674"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ReverseSSH"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Run" ascii //weight: 1
        $x_1_2 = "main.Fork" ascii //weight: 1
        $x_1_3 = "reverse_ssh" ascii //weight: 1
        $x_1_4 = "client/handlers.LocalForward" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_ReverseSSH_D_2147946603_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ReverseSSH.D!MTB"
        threat_id = "2147946603"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ReverseSSH"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createReversePortForwardingCallback" ascii //weight: 1
        $x_1_2 = "main.createSSHSessionHandler" ascii //weight: 1
        $x_1_3 = "github.com/Fahrj/reverse-ssh" ascii //weight: 1
        $x_1_4 = "main.createPasswordHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


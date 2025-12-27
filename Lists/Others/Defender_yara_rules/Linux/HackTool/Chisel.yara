rule HackTool_Linux_Chisel_A_2147794676_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Chisel.A"
        threat_id = "2147794676"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Chisel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chisel server" wide //weight: 10
        $x_10_2 = "chisel client" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Linux_Chisel_C_2147924004_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Chisel.C"
        threat_id = "2147924004"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Chisel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chisel-v" ascii //weight: 10
        $x_1_2 = "tunnel.Config" ascii //weight: 1
        $x_1_3 = "syscall.Socket" ascii //weight: 1
        $x_1_4 = "syscall.Accept" ascii //weight: 1
        $x_1_5 = "syscall.recvfrom" ascii //weight: 1
        $x_1_6 = "syscall.sendfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_Chisel_B_2147928935_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Chisel.B"
        threat_id = "2147928935"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Chisel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 68 00 69 00 73 00 65 00 6c 00 [0-64] 20 00 73 00 65 00 72 00 76 00 65 00 72 00}  //weight: 10, accuracy: Low
        $x_10_2 = {63 00 68 00 69 00 73 00 65 00 6c 00 [0-64] 20 00 63 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Linux_Chisel_B_2147945396_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Chisel.B!MTB"
        threat_id = "2147945396"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jpillora/chisel/client" ascii //weight: 1
        $x_1_2 = "jpillora/chisel/share/tunnel.NewProxy" ascii //weight: 1
        $x_1_3 = "chisel-masterwoserver/main.go" ascii //weight: 1
        $x_1_4 = "chisel/share/tunnel.listenUDP" ascii //weight: 1
        $n_2_5 = "github.com/portainer/agent/" ascii //weight: -2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}


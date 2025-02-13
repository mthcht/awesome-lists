rule Misleading_Linux_Chisel_A_347929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Linux/Chisel.A!MTB"
        threat_id = "347929"
        type = "Misleading"
        platform = "Linux: Linux platform"
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "httputil.NewSingleHostReverseProxy" ascii //weight: 2
        $x_1_2 = "chisel/share/tunnel/tunnel.go" ascii //weight: 1
        $x_1_3 = "chisel/server.NewServer" ascii //weight: 1
        $x_1_4 = "tunnel.(*Tunnel).keepAliveLoop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Misleading_Linux_Chisel_B_348954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Linux/Chisel.B!MTB"
        threat_id = "348954"
        type = "Misleading"
        platform = "Linux: Linux platform"
        family = "Chisel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LetsEncrypt.func1" ascii //weight: 2
        $x_1_2 = "NewCBCEncrypter" ascii //weight: 1
        $x_1_3 = "chisel/server.NewServer" ascii //weight: 1
        $x_1_4 = "man-in-the-middle attacks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


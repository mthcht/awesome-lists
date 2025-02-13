rule VirTool_Win64_Ligelesz_A_2147907203_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ligelesz.A!MTB"
        threat_id = "2147907203"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ligelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ligolo-ng/cmd/agent" ascii //weight: 1
        $x_1_2 = "protocol.LigoloDecoder" ascii //weight: 1
        $x_1_3 = ").RemoteAddr" ascii //weight: 1
        $x_1_4 = "SetSessionTicket" ascii //weight: 1
        $x_1_5 = "maxPayloadSizeForWrite" ascii //weight: 1
        $x_1_6 = "ligolo-ng/pkg/relay" ascii //weight: 1
        $x_1_7 = "ligolo-ng/pkg/agent.HandleConn" ascii //weight: 1
        $x_1_8 = "ListenAndServe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Ligelesz_B_2147919484_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ligelesz.B!MTB"
        threat_id = "2147919484"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ligelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").RemoteAddr" ascii //weight: 1
        $x_1_2 = "maxPayloadSizeForWrite" ascii //weight: 1
        $x_1_3 = "ListenAndServe" ascii //weight: 1
        $x_1_4 = "SetSessionTicket" ascii //weight: 1
        $x_1_5 = ".StartLigolo" ascii //weight: 1
        $x_1_6 = ".verifyTlsCertificate" ascii //weight: 1
        $x_1_7 = ".startSocksProxy" ascii //weight: 1
        $x_1_8 = ".handleRelay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


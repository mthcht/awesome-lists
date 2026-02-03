rule Backdoor_Linux_Merlin_B_2147962239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Merlin.B!MTB"
        threat_id = "2147962239"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Merlin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Otpau5iaGuO.(*http2ClientConn).Ping" ascii //weight: 1
        $x_1_2 = "Hrx6GzXD.(*PingFrame).IsAck" ascii //weight: 1
        $x_1_3 = "Otpau5iaGuO.(*http2ClientConn).ReserveNewRequest" ascii //weight: 1
        $x_1_4 = "Otpau5iaGuO.(*http2Transport).NewClientConn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule HackTool_Win64_SecureSockFunnel_ARA_2147963375_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/SecureSockFunnel.ARA!MTB"
        threat_id = "2147963375"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SecureSockFunnel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[shell] session could not get fiber remote endpoint" ascii //weight: 2
        $x_2_2 = "[shell] session create write side of named pipe" ascii //weight: 2
        $x_2_3 = "gateway_ports" ascii //weight: 2
        $x_2_4 = "stream_listener" ascii //weight: 2
        $x_2_5 = "stream_forwarder" ascii //weight: 2
        $x_3_6 = "[socks v4] session Bind not implemented yet" ascii //weight: 3
        $x_3_7 = "[socks v5] session Bind not implemented yet" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}


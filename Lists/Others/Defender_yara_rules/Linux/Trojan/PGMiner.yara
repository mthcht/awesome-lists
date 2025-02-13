rule Trojan_Linux_PGMiner_A_2147771160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PGMiner.A!MTB"
        threat_id = "2147771160"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PGMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/tmp/.X11-unix/22" ascii //weight: 5
        $x_5_2 = "abroxu(cmd_output text);COPY abroxu FROM PROGRAM" ascii //weight: 5
        $x_1_3 = "172.16.0.0/12" ascii //weight: 1
        $x_1_4 = "192.168.0.0/16" ascii //weight: 1
        $x_1_5 = "10.%d.0.0/16" ascii //weight: 1
        $x_1_6 = "Pa$$word123456" ascii //weight: 1
        $x_1_7 = "!@#$1q2w3e4r5t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


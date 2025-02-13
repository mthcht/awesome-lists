rule Backdoor_Linux_Dklkt_A_2147830761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Dklkt.A!xp"
        threat_id = "2147830761"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Dklkt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DDOS_STOP" ascii //weight: 1
        $x_1_2 = "BIG_Flood" ascii //weight: 1
        $x_1_3 = "TcpFlood" ascii //weight: 1
        $x_1_4 = "UdpFlood" ascii //weight: 1
        $x_1_5 = "rm -rf .b64" ascii //weight: 1
        $x_1_6 = ":SIMPLE_DDOS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


rule DDoS_Linux_Ddostf_A_2147823255_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Ddostf.A!xp"
        threat_id = "2147823255"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Ddostf"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ddos.tf" ascii //weight: 2
        $x_1_2 = "UDP-Flow" ascii //weight: 1
        $x_1_3 = "SYN-Flow" ascii //weight: 1
        $x_1_4 = "TCP_Flood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Ddostf_B_2147824590_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Ddostf.B!xp"
        threat_id = "2147824590"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Ddostf"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 89 44 24 20 e8 ?? ?? ?? 00 c7 44 24 08 10 00 00 00 89 c3 8d 44 24 1c 89 44 24 04 89 1c 24 e8 ?? ?? ?? 00 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f6 8d bc 27 00 00 00 00 80 3d e0 fa 0f 08 00 75 65 55 89 e5 53 bb 28 f0 0f 08 83 ec 14 a1 e4 fa 0f 08 81 eb 20 f0 0f 08 c1 fb 02 83 eb 01 39 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


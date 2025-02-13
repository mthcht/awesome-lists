rule DDoS_Linux_Kaiten_2147497851_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Kaiten"
        threat_id = "2147497851"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Kaiten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "SPOOFS me manually." ascii //weight: 4
        $x_2_2 = ">bot +std <target> <port> <secs>" ascii //weight: 2
        $x_1_3 = "/etc/rc.d/rc.local" ascii //weight: 1
        $x_1_4 = {49 52 43 20 42 6f 74 00}  //weight: 1, accuracy: High
        $x_2_5 = "[UNK]Done hitting" ascii //weight: 2
        $x_2_6 = "[UNK]Done Slamming" ascii //weight: 2
        $x_2_7 = "[NRPE] Attack Stopped" ascii //weight: 2
        $x_2_8 = "been_there_done_that" ascii //weight: 2
        $x_2_9 = "kaiten.c" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Kaiten_A_2147809995_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Kaiten.A!MTB"
        threat_id = "2147809995"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Kaiten"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 16 c7 44 24 04 09 00 00 00 c7 04 24 00 00 00 00 e8 ?? ?? 00 00 eb 3c a1 ?? ?? 06 08 c7 44 24 18 02 00 00 00 c7 44 24 14 03 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 02 00 00 00 89 44 24 08 c7 44 24 04 bc a1 05 08 8b 45 08 89 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = "/etc/rc.d/rc.local" ascii //weight: 1
        $x_1_3 = "Dismay's IRC Bot" ascii //weight: 1
        $x_1_4 = "bot +unknown <target> <secs>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


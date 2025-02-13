rule DDoS_Linux_Chalubo_A_2147763917_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Chalubo.A!MTB"
        threat_id = "2147763917"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Chalubo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dhcprenew" ascii //weight: 1
        $x_10_2 = {3a 38 38 35 32 2f 52 54 45 47 46 4e 30 31 3b [0-4] 3a 2f 2f [0-21] 2e 63 6f 6d 3a 38 38 35 32 2f 52 54 45 47 46 4e 30 31}  //weight: 10, accuracy: Low
        $x_1_3 = "/data/local/tmp/tmp.l" ascii //weight: 1
        $x_1_4 = "/tmp/tmpnam_XXXXXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Chalubo_DS_2147809148_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Chalubo.DS!MTB"
        threat_id = "2147809148"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Chalubo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f}  //weight: 1, accuracy: High
        $x_1_2 = "task_decrypt" ascii //weight: 1
        $x_1_3 = "/tmp/tmpnam_XXXXXX" ascii //weight: 1
        $x_1_4 = "/tmp/tmpfile_XXXXXX" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f [0-21] 3a 38 38 35 32 2f [0-8] 2f [0-8] 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_6 = "attack_dns" ascii //weight: 1
        $x_1_7 = "attack_udp" ascii //weight: 1
        $x_1_8 = "easy_attack_syn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


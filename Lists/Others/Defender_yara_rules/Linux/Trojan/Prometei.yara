rule Trojan_Linux_Prometei_A_2147771319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Prometei.A!MTB"
        threat_id = "2147771319"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "start_mining" ascii //weight: 2
        $x_2_2 = "stop_mining" ascii //weight: 2
        $x_1_3 = "gb7ni5rgeexdcncj.onion/cgi-bin/prometei.cgi " ascii //weight: 1
        $x_1_4 = "//mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cgi" ascii //weight: 1
        $x_1_5 = "crontab task.cron" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Prometei_B_2147893690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Prometei.B!MTB"
        threat_id = "2147893690"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 44 4e 67 b1 be 50 35 04 99 44 64 48 5b 2d 79 b4 81 ce f7 c5 16 ac 34 9f ce 4b ef 28 f0 26 56 fd cb 8f c0 c0 08 df 04 a8 dd f0 bc eb 68 ee 42}  //weight: 1, accuracy: High
        $x_1_2 = {43 40 a3 46 f3 4d a7 40 66 64 cb 20 2f d0 f3 bc b3 55 0a 2e 36 5c 68 11 16 93 01 39 c6 52 8e fc bd 60 77 93 f2 08 c3 c6 2a 34 9b 47 35 df 8c 78 2f e7 a0 86 44 cc 3e a4 2b 0d 22 4f 60 83 92 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


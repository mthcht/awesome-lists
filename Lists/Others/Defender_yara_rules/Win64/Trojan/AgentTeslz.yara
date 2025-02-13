rule Trojan_Win64_AgentTeslz_A_2147919784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTeslz.A!MTB"
        threat_id = "2147919784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTeslz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 1e 00 81 01 f1 01 80 60 9c a1 21 f4 e8 0c 11 00 60 0a c8 08 20 e4 92 ba 87 26 13 03 e8 5a 19 df 9d 76 76 5b fc ed cd ae 9b 62 73 6f da a5 07 bf 7e 71 6c 76 fb 06 97 cf 11 d0 fd 52 9a 01 fa f7 c1 9f 30 9e 2b 64 8c fb d2 73 19 73 7d 88 1c 3a 27 89 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


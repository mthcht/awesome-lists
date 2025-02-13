rule Backdoor_Linux_BitXo_A_2147819491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BitXo.A!MTB"
        threat_id = "2147819491"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BitXo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 d3 4f a7 a2 bc 4d fa 40 cf a6 32 31 e9 59 a1}  //weight: 1, accuracy: High
        $x_1_2 = "/dev/urandom" ascii //weight: 1
        $x_1_3 = "/var/tmp/.unetns" ascii //weight: 1
        $x_1_4 = "M3T4M0RPH1N3.ko" ascii //weight: 1
        $x_1_5 = "b4d4b1t" ascii //weight: 1
        $x_1_6 = {01 10 8f e0 01 20 a0 e3 10 80 8d e5 0c 40 8d e5 08 00 8d e5 04 00 8d e5 00 00 8d e5 01 00 70 e3 00 70 a0 e1 [0-5] 00 10 a0 e1 08 30 a0 e1 05 20 a0 e1 04 00 a0 e1 [0-5] 01 00 70 e3 [0-5] 01 00 a0 e3 [0-5] 08 30 a0 e1 05 20 a0 e1 07 10 a0 e1 04 00 a0 e1 [0-5] 01 00 70 e3}  //weight: 1, accuracy: Low
        $x_1_7 = {08 44 9f e5 04 00 a0 e1 90 02 05 00 00 50 e3 90 02 05 f8 23 9f e5 f8 03 9f e5 02 20 8f e0 c8 3e 52 e5 03 11 82 e0 c4 4e 01 e5 3b 1d 42 e2 08 10 41 e2 83 10 81 e0 b0 01 c1 e1 03 11 82 e0 08 00 a0 e3 01 30 83 e2 b0 0e 01 e5 c8 3e 42 e5 c4 a3 9f e5 c4 83 9f e5 c4 53 9f e5 c4 93 9f e5 0a a0 8f e0 08 80 8f e0 00 70 a0 e3 01 40 a0 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


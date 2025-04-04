rule Trojan_MacOS_SAgnt_B_2147850535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.B!MTB"
        threat_id = "2147850535"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2f 67 65 61 63 6f 6e 5f [0-16] 2f 6d 61 69 6e 2e 67 6f}  //weight: 5, accuracy: Low
        $x_5_2 = "cs_gencon/main.go" ascii //weight: 5
        $x_1_3 = "runtime.persistentalloc" ascii //weight: 1
        $x_1_4 = "process).kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_SAgnt_C_2147888515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.C!MTB"
        threat_id = "2147888515"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.createPlist" ascii //weight: 1
        $x_1_2 = "MPAgent.go" ascii //weight: 1
        $x_1_3 = "stopad" ascii //weight: 1
        $x_1_4 = "libc_execve_trampoline" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SAgnt_D_2147927666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.D!MTB"
        threat_id = "2147927666"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 8a 31 40 84 f6 74 ?? 40 38 f0 75 ?? 48 ff c1 8a 02 48 ff c2 84 c0 75 ?? 31 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {89 d1 80 e1 38 49 89 f0 49 d3 e8 44 30 07 48 83 c2 08 48 ff c7 48 83 fa 50 75 ?? c6 40 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SAgnt_AC_2147929100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.AC!MTB"
        threat_id = "2147929100"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 56 53 50 48 c7 04 24 00 00 00 00 48 83 fe 09 b8 08 00 00 00 48 0f 43 c6 48 89 e1 48 89 fa 48 89 cf 48 89 c6 48 89 d3 e8 59 90 25 00 89 c1 31 c0 85 c9 75 17 4c 8b 34 24 4d 85 f6 74 0e 4c 89 f7 48 89 de e8 45 8e 25 00 4c 89 f0}  //weight: 1, accuracy: High
        $x_1_2 = {48 85 db 0f 88 43 01 00 00 49 89 f4 0f b6 05 7b 7d 3b 00 be 01 00 00 00 48 89 df e8 36 fe ff ff 48 85 c0 0f 84 28 01 00 00 49 89 c7 48 89 c7 4c 89 e6 48 89 da e8 36 8f 25 00 49 83 3e 00 74 09 49 8b 7e 08 e8 97 8e 25 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SAgnt_E_2147935634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.E!MTB"
        threat_id = "2147935634"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 00 80 d2 a9 f4 85 d2 29 30 b1 f2 e9 a7 df f2 a9 3d e9 f2 ea 03 00 aa 0b 09 7d 92 2b 25 cb 9a 4c 01 40 39 8b 01 0b 4a 4b 15 00 38 08 21 00 91 1f a1 01 f1 21 ff ff 54 1f 34 00 39 e8 03 00 91}  //weight: 1, accuracy: High
        $x_1_2 = {a8 02 40 f9 e0 03 15 aa 00 01 3f d6 08 08 40 39 28 01 00 34 08 00 40 39 a9 09 80 52 08 01 09 4a 08 00 00 39 08 04 40 39 08 79 19 52 08 04 00 39 1f 08 00 39 a8 83 03 d1 08 05 00 d1 09 1d 40 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SAgnt_F_2147937881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.F!MTB"
        threat_id = "2147937881"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 7d d8 4c 39 ff 0f 8d 53 01 00 00 45 31 f6 48 89 f8 31 db 48 85 ff 0f 88 37 01 00 00 41 8a 4c 04 08 8d 51 d0 80 fa 0a 73 4d 0f b6 c9 89 da 48 c1 eb 20 48 01 d2 48 8d 14 92 89 d6 48 c1 ea 20 48 8d 1c 9b 48 8d 14 5a 48 89 d3 48 c1 eb 20 48 c1 e2 20 48 09 f2 4d 01 f6 4f 8d 34 b6 48 83 c1 d0 48 01 d1 49 11 de 48 89 cb 48 ff c0 49 39 c7}  //weight: 1, accuracy: High
        $x_1_2 = {49 d3 e2 4c 89 d7 48 c1 ef 20 48 89 f0 31 d2 48 f7 f7 49 89 c1 48 89 d0 45 89 d7 45 89 c3 4c 89 ca 49 0f af d7 4c 0f a4 c0 20 48 39 d0 73 25 4c 01 d0 4c 39 d0 41 0f 93 c0 48 39 d0 0f 92 c3 31 f6 44 20 c3 49 0f 45 f2 48 01 f0 0f b6 f3 48 f7 d6 49 01 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SAgnt_G_2147937883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgnt.G!MTB"
        threat_id = "2147937883"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 d3 e4 4c 89 e7 48 c1 ef 20 48 89 d0 31 d2 48 f7 f7 49 89 c1 48 89 d0 45 89 e2 45 89 c3 4c 89 ca 49 0f af d2 4c 0f a4 c0 20 48 39 d0 73 27 4c 01 e0 4c 39 e0 41 0f 93 c0 48 39 d0 41 0f 92 c7 31 db 45 20 c7 49 0f 45 dc 48 01 d8 41 0f b6 df 48 f7 d3 49 01 d9}  //weight: 1, accuracy: High
        $x_1_2 = {48 29 d0 31 d2 48 f7 f7 4c 0f af d0 48 c1 e2 20 4c 09 da 4c 39 d2 73 25 4c 01 e2 4c 39 e2 41 0f 93 c0 4c 39 d2 0f 92 c3 31 ff 44 20 c3 49 0f 45 fc 48 01 fa 0f b6 fb 48 f7 d7 48 01 f8 4c 29 d2 49 c1 e1 20 49 09 c1 48 d3 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


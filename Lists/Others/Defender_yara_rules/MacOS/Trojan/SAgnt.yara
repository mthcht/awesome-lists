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


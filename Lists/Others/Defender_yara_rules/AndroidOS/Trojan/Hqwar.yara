rule Trojan_AndroidOS_Hqwar_B_2147852378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hqwar.B!MTB"
        threat_id = "2147852378"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 04 61 57 04 00 b1 48 48 04 00 06 14 05 31 22 0b 00 92 05 05 08 dc 07 06 01 48 07 03 07 14 09 [0-2] 0e 00 92 08 08 09 da 09 05 37 b0 98 b7 74 8d 44 4f 04 01 06 b0 85 d8 09 05 fe d8 06 06 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 09 07 09 14 0a 27 40 08 00 b1 2a b0 23 b1 a3 b0 63 b7 98 8d 88 4f 08 05 00 14 08 f5 d0 01 00 32 83 [0-2] b0 23 81 28 81 3a be a8 14 08 eb e8 01 00 ?? 09 06 03 b1 29 b0 89 01 92}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_AndroidOS_Hqwar_J_2147906201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hqwar.J!MTB"
        threat_id = "2147906201"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inj_dnlader" ascii //weight: 1
        $x_1_2 = "faknotiactivity" ascii //weight: 1
        $x_1_3 = "forc_activateacc" ascii //weight: 1
        $x_1_4 = "ice/smsplus" ascii //weight: 1
        $x_1_5 = "/nb6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hqwar_K_2147923685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hqwar.K!MTB"
        threat_id = "2147923685"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/mem/installdropsession" ascii //weight: 1
        $x_1_2 = {1a 01 05 14 16 02 00 00 16 04 ff ff 07 80 74 06 ac 02 00 00 0c 08 6e 10 87 16 06 00 0c 00 6e 20 bc 02 70 00 0c 07 15 00 60 00 23 00 10 07 6e 20 f9 20 07 00 0a 01 3a 01 07 00 12 02 6e 40 ff 20 08 12 28 f6 38 07 05 00 6e 10 f8 20 07 00 38 08 05 00 6e 10 fe 20 08 00 0e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hqwar_L_2147924406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hqwar.L!MTB"
        threat_id = "2147924406"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/mem/installdropsession" ascii //weight: 1
        $x_1_2 = {05 00 0c 05 6e 10 ?? 02 05 00 0c 05 22 00 ?? ?? 12 11 70 20 ?? 02 10 00 6e 20 ?? 02 05 00 0a 00 6e 20 ?? 02 05 00 0c 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hqwar_M_2147926129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hqwar.M!MTB"
        threat_id = "2147926129"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 09 02 05 d0 7a d7 dd dc 0b 05 02 48 0b 01 0b 14 0c a5 6f 0a 00 91 0d 0a 07 b1 cd 92 0c 0a 07 b0 cd da 0d 0d 00 b0 9d b3 aa b3 8a df 09 0a 01 b0 9d 94 09 07 07 b0 9d 97 09 0d 0b 8d 99 4f 09 04 05 13 09 26 05 b3 79 d8 05 05 01}  //weight: 1, accuracy: High
        $x_1_2 = {13 09 27 00 35 98 ?? ?? d3 59 85 22 d0 99 f6 de 93 07 03 07 91 07 09 07 d8 08 08 01 28 f2 36 35 ?? ?? d8 08 05 30 d8 08 08 1a b0 78 b0 83 12 18 33 37 ?? ?? ?? 09 08 03 b0 79 91 05 09 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


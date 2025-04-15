rule Trojan_MSIL_Bulz_AZ_2147838081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.AZ!MTB"
        threat_id = "2147838081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 0a 06 04 6f 20 00 00 0a 0b 00 07 0c 16 0d 2b 1e 08 09 9a 13 04 00 02 6f 21 00 00 0a 11 04 6f 22 00 00 0a 6f 23 00 00 0a 26 00 09 17 58 0d 09 08 8e 69 32 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_PSKN_2147845491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.PSKN!MTB"
        threat_id = "2147845491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 ab 24 00 70 02 7b 54 01 00 04 6f 30 01 00 06 28 1c 01 00 0a 28 ?? ?? ?? 0a 0d 07 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 02 07 28 6f 01 00 06 0c 02 7b 54 01 00 04 08 28 ?? ?? ?? 0a 6f 33 01 00 06 26 de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_AB_2147849937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.AB!MTB"
        threat_id = "2147849937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 52 00 06 28 ?? ?? ?? 06 0b 07 17 2e 0a 07 20 01 80 ff ff fe 01 2b 01 17 0c 08 2c 32 00 02 7b 04 00 00 04 17 73 10 00 00 0a 0d 02 7b 04 00 00 04 18 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_PSRQ_2147850753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.PSRQ!MTB"
        threat_id = "2147850753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 73 0f 00 00 0a 72 01 00 00 70 28 10 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_SPWR_2147890120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.SPWR!MTB"
        threat_id = "2147890120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 28 13 00 00 0a 0a 28 14 00 00 0a 0b 06 07 28 11 00 00 0a 0c 08 0d 2b 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_PSXX_2147891524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.PSXX!MTB"
        threat_id = "2147891524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 0a 0a 1f 1c 06 5a 20 19 01 00 00 2e 23 73 16 00 00 0a 72 30 02 00 70 73 17 00 00 0a 72 c8 01 00 70 6f ?? 00 00 0a 20 40 0d 03 00 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_ARA_2147893344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.ARA!MTB"
        threat_id = "2147893344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Point_Temp_Spoofer.Properties.Resources" wide //weight: 2
        $x_2_2 = "logs.txt" wide //weight: 2
        $x_2_3 = "/cdn.discordapp.com/attachments/" wide //weight: 2
        $x_2_4 = "/Cleaner_1.bat?ex=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_PTAG_2147894663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.PTAG!MTB"
        threat_id = "2147894663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 07 00 00 70 28 ?? 00 00 0a 73 07 00 00 0a 72 49 00 00 70 6f 08 00 00 0a 74 01 00 00 1b 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 72 8f 00 00 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_AMBA_2147895355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.AMBA!MTB"
        threat_id = "2147895355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 11 01 03 11 01 91 11 03 61 d2 9c 38}  //weight: 1, accuracy: High
        $x_1_2 = {11 02 11 09 11 01 94 58 11 05 11 01 94 58 20 00 01 00 00 5d 13 02}  //weight: 1, accuracy: High
        $x_1_3 = {11 09 11 09 11 00 94 11 09 11 02 94 58 20 00 01 00 00 5d 94 13 03}  //weight: 1, accuracy: High
        $x_1_4 = "Ifmzuxpdqctmqn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_KAB_2147895796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.KAB!MTB"
        threat_id = "2147895796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 05 9a 0b 07 17 8d ?? 00 00 01 13 06 11 06 16 20 ?? ?? 00 00 9d 11 06 6f ?? 00 00 0a 16 9a 0c 07 17 8d ?? 00 00 01 13 07 11 07 16 20 ?? ?? 00 00 9d 11 07 6f ?? 00 00 0a 17 9a 0d 08 09 28 ?? 00 00 06 11 05 17 58 13 05 11 05 11 04 8e 69 32 ad}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_KAD_2147895800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.KAD!MTB"
        threat_id = "2147895800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 1c 06 1c 95 07 1c 95 58 20 ?? ?? ?? ?? 5a 9e 06 1d 06 1d 95 07 1d 95 61 20 ?? ?? ?? ?? 58 9e 11 0b}  //weight: 5, accuracy: Low
        $x_5_2 = {3b 48 6b ed 42 19 ab 06 56 e3 a8 f5 98 a3 cd 7f 10 ee 0c b4 74 27 46 f7 49 56 db d2 51 4b b2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_NB_2147896153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.NB!MTB"
        threat_id = "2147896153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 37 01 00 04 02 28 ?? ?? 00 06 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 6f ?? ?? 00 06 26 02 16}  //weight: 5, accuracy: Low
        $x_1_2 = "VanillaRat.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_NB_2147896153_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.NB!MTB"
        threat_id = "2147896153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 06 16 20 00 04 00 00 6f 9a 00 00 0a 25 13 07 16 fe 02 13 0b 11 0b 2d c6}  //weight: 3, accuracy: High
        $x_1_2 = "$e4f7f555-8a23-4a9b-9a3c-065e44fc1244" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_NB_2147896153_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.NB!MTB"
        threat_id = "2147896153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6f 24 00 00 0a 73 1b 00 00 0a 0c 08 07 6f 25 00 00 0a 25 26 1f 4c 28 18 00 00 06 73 26 00 00 0a 0d 09 02 1f 50 28 18 00 00 06 02 8e 69 1f 54 28 18 00 00 06 59 6f 1d 00 00 0a}  //weight: 3, accuracy: High
        $x_1_2 = "Loader CSGO v2- CheatsTDM.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_NB_2147896153_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.NB!MTB"
        threat_id = "2147896153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {73 a1 00 00 0a 13 08 11 08 72 d4 07 00 70 6f a2 00 00 0a 00 11 08 72 e6 07 00 70 7e 0a 00 00 04 28 9f 00 00 0a 72 0a 08 00 70 28 91 00 00 0a 6f a3 00 00 0a}  //weight: 3, accuracy: High
        $x_1_2 = "$bad8e554-94a8-4ba0-9e4b-7acd60eb913e" ascii //weight: 1
        $x_1_3 = "PING!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_AMAC_2147896266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.AMAC!MTB"
        threat_id = "2147896266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 9b 00 00 00 00 73 ?? ?? ?? ?? 0d 00 08 16 73 ?? 00 00 0a 73 ?? 00 00 0a 13 04 00 11 04 09 6f ?? 00 00 0a 00 00 de 10 16 2d 0b 11 04 2c 08 11 04 6f ?? 00 00 0a 00 dc 09 6f ?? 00 00 0a 13 05 de 1f}  //weight: 1, accuracy: Low
        $x_1_2 = {00 15 2c fc 2b 1c 72 ?? ?? ?? ?? 7e ?? 00 00 04 2b 17 2b 1c 2b 1d 74 ?? 00 00 1b 2b 19 2b 00 2b 18 2a 28 ?? 00 00 06 2b dd 6f ?? 00 00 0a 2b e2 0a 2b e1 06 2b e0 0b 2b e4 07 2b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_KAA_2147896405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.KAA!MTB"
        threat_id = "2147896405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e7}  //weight: 5, accuracy: High
        $x_5_2 = {11 04 11 11 11 04 11 11 91 1f 7a 61 d2 9c 11 11 17 58 13 11 11 11 11 04 8e 69 32 e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_PTBX_2147896542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.PTBX!MTB"
        threat_id = "2147896542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 11 00 00 0a 02 50 6f 12 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_AMBB_2147897419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.AMBB!MTB"
        threat_id = "2147897419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 1f 3a 28 ?? 00 00 0a 28 ?? 00 00 0a 11 07 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 11 05 17 58 13 05 11 05 11 04 6f ?? 00 00 0a 32 92 12 01 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0c 02 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_PTFX_2147900829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.PTFX!MTB"
        threat_id = "2147900829"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2c 07 02 03 28 ?? 00 00 0a 73 1a 00 00 0a 25 02 6f 1b 00 00 0a 25 17 6f 1c 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_GZF_2147903162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.GZF!MTB"
        threat_id = "2147903162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 12 02 06 1f 18 11 05 58 58 1f 28 11 11 5a 58 11 12 16 1f 28 28 ?? ?? ?? 0a 00 11 12 1f 0c 28 ?? ?? ?? 0a 13 13 11 12 1f 10 28 ?? ?? ?? 0a 13 14 11 12 1f 14 28 ?? ?? ?? 0a 13 15 11 14 8d ?? ?? ?? ?? 13 16 02 11 15 11 16 16 11 16 8e 69 28 ?? ?? ?? 0a 00 11 0c 11 06 11 13 6a 58 11 16 11 16 8e 69 16 6a 28 ?? ?? ?? 06 26 00 11 11 17 58 68 13 11 11 11 11 04 fe 04 13 17 11 17}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_KAH_2147903841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.KAH!MTB"
        threat_id = "2147903841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 9a 14 17 8d ?? 00 00 01 0d 09 16 02 8c ?? 00 00 01 a2 09 6f ?? 00 00 0a 74 ?? 00 00 1b 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_SG_2147904861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.SG!MTB"
        threat_id = "2147904861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0a 72 21 13 00 70 28 88 00 00 0a 28 7e 00 00 0a 72 72 09 00 70 72 e8 04 00 70 6f 6d 00 00 0a 72 4b 13 00 70}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_AYA_2147925309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.AYA!MTB"
        threat_id = "2147925309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Remote_Shell_Socket.Resources" wide //weight: 2
        $x_1_2 = "$e42f530b-df4e-41c7-8178-457d121c268e" ascii //weight: 1
        $x_1_3 = "/c taskkill -f -im RuntimeBroker.exe & Exit" wide //weight: 1
        $x_1_4 = "Injecting successfuly" wide //weight: 1
        $x_1_5 = "TakeScreenShot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_ARAZ_2147928123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.ARAZ!MTB"
        threat_id = "2147928123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ec632fd9-1694-4f4a-9bff-f20600e37981" ascii //weight: 2
        $x_2_2 = "sihost.Resources.resources" ascii //weight: 2
        $x_2_3 = "\\sihost.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_KAI_2147929022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.KAI!MTB"
        threat_id = "2147929022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0d 91 08 08 11 0a 84 95 08 11 08 84 95 d7 6e 20 ff 00 00 00 6a 5f 84 95 61 86 9c 11 0d 17 d6 13 0d 2b 8a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_NIT_2147929714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.NIT!MTB"
        threat_id = "2147929714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 6f 59 00 00 0a 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0b 06 73 93 00 00 0a 0c 08 07 6f ?? 00 00 0a 28 ?? 00 00 06 0d 2b 00 09 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "encryption" ascii //weight: 1
        $x_1_3 = "chatsend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_SWA_2147930140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.SWA!MTB"
        threat_id = "2147930140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 11 0a 1f 28 5a 58 13 0b 28 20 00 00 0a 11 04 11 0b 1e 6f 21 00 00 0a 17 8d 28 00 00 01 6f 22 00 00 0a 13 0c 28 20 00 00 0a 11 0c 6f 23 00 00 0a 28 24 00 00 0a 72 16 01 00 70 28 25 00 00 0a 39 3c 00 00 00 11 04 11 0b 1f 14 58 28 1f 00 00 0a 13 0d 11 04 11 0b 1f 10 58 28 1f 00 00 0a 13 0e 11 0e 8d 1c 00 00 01 0c 11 04 11 0d 6e 08 16 6a 11 0e 6e 28 26 00 00 0a 17 13 09 38 0f 00 00 00 11 0a 17 58 13 0a 11 0a 11 06 3f 6f ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bulz_NITA_2147931301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bulz.NITA!MTB"
        threat_id = "2147931301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "resworBxednaY" wide //weight: 2
        $x_2_2 = "xednaY" wide //weight: 2
        $x_1_3 = "drocsid" wide //weight: 1
        $x_1_4 = "btpdrocsid" wide //weight: 1
        $x_1_5 = "yranacdrocsid" wide //weight: 1
        $x_1_6 = "kill.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


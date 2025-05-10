rule Trojan_MSIL_CrimsonRat_YNB_2147828104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.YNB!MTB"
        threat_id = "2147828104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 91 28 ?? ?? ?? 0a 0c 06 07 08 9d 00 07 17 58 0b 07 02 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRat_AYN_2147832619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.AYN!MTB"
        threat_id = "2147832619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 05 9a 0c 00 08 6f ?? ?? ?? 0a 16 fe 01 13 06 11 06 2d 23 00 06 08}  //weight: 2, accuracy: Low
        $x_1_2 = "GetDrives" ascii //weight: 1
        $x_1_3 = "aridsplyar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRat_AFFT_2147834470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.AFFT!MTB"
        threat_id = "2147834470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 04 05 28 ?? ?? ?? 06 0b 07 2c 04 17 0c 2b 14 00 06 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRat_MA_2147848599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.MA!MTB"
        threat_id = "2147848599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0e 11 0e 16 1f 2d 9d 11 0e 6f ?? ?? ?? 0a 17 9a 0a 00 06 19 17 6f ?? ?? ?? 0a 0a 06 18}  //weight: 5, accuracy: Low
        $x_1_2 = "bdd3f9ae-a991-4b53-bc80-9ab8bd76961c" ascii //weight: 1
        $x_1_3 = "injavte_mnr.Properties" ascii //weight: 1
        $x_1_4 = "scareenSize" ascii //weight: 1
        $x_1_5 = "remaove_file" ascii //weight: 1
        $x_1_6 = "usaer_info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRat_ABPT_2147896712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.ABPT!MTB"
        threat_id = "2147896712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 00 6f 00 75 00 6e 00 74 00 64 00 6f 00 77 00 6e 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 00 03 32 00 00 03 33 00 00 0d 61 00 6c 00 61 00 72 00 6d 00 65 00 00 15 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 00 0b 63 00 6c 00 6f 00 73 00 65 00 00 11 63 00 6f 00 72 00 6e 00 65 00 74 00 61 00 73 00 00 17 66 00 65 00 72 00 72 00 61 00 6d 00 65 00 6e 00 74 00 61 00 73 00 00 15 66 00 75 00 6c 00 6c 00 73 00 63 00 72 00 65 00 65 00 6e 00 00 0b 66 00 75 00 6e 00 64 00 6f 00 00 0b 6c 00 61 00 70 00 69 00 73 00 00 09 6d 00 6f 00 64 00 65 00 00 07 6f 00 6e 00 65}  //weight: 2, accuracy: High
        $x_2_2 = {70 00 61 00 6c 00 65 00 74 00 61 00 2d 00 64 00 65 00 2d 00 63 00 6f 00 72 00 65 00 73 00 01 0b 70 00 69 00 73 00 63 00 61 00 00 2b 70 00 6f 00 6e 00 74 00 6f 00 2d 00 64 00 65 00 2d 00 69 00 6e 00 74 00 65 00 72 00 72 00 6f 00 67 00 61 00 63 00 61 00 6f 00 01 57 50 00 6f 00 72 00 74 00 75 00 67 00 61 00 6c 00 2d 00 54 00 65 00 63 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 61 00 20 00 28 00 54 00 72 00 61 00 6e 00 73 00 70 00 61 00 72 00 65 00 6e 00 74 00 65 00 29 00 20 00 2d 00 20 00 42 00 52 00 41 00 4e 00 43 00 4f 00 01 0b 74 00 65 00 78 00 74 00 6f 00 00 11 76 00 65 00 72 00 6d 00 65 00 6c 00 68 00 6f}  //weight: 2, accuracy: High
        $x_1_3 = "Countdown.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRat_PSEC_2147899359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.PSEC!MTB"
        threat_id = "2147899359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 73 29 00 00 0a 0a 73 25 00 00 06 0b 1b 8d 3b 00 00 01 0c 06 08 16 1b 6f 2a 00 00 0a 26 07 08 6f 2b 00 00 06 16 6a 0d 16 13 06 2b 1d 06 6f 2b 00 00 0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 0d 11 06 17 58 13 06 11 06 1e 32 de}  //weight: 5, accuracy: High
        $x_1_2 = "GetEnumerator" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "WriteLine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRat_NC_2147932478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.NC!MTB"
        threat_id = "2147932478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7b 83 48 00 04 39 85 fe ff ff 26 20 01 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "Debugger Detected" wide //weight: 1
        $x_1_3 = "$24a6f560-a346-46b0-aafb-d801ee261903" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRat_A_2147935989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.A!MTB"
        threat_id = "2147935989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 31 00 00 01 0a 02 02 7b 2d 00 00 04 06 16 1b 6f c7 00 00 0a 7d 35 00 00 04 06 16 28 c8 00 00 0a 0b 07 8d 31 00 00 01 0c 16 0d 07 13 04 2b 42}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRat_ACR_2147941080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRat.ACR!MTB"
        threat_id = "2147941080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 41 00 11 04 02 7b ?? 00 00 04 30 04 11 04 2b 06 02 7b ?? 00 00 04 13 05 02 02 7b ?? 00 00 04 09 06 11 05 6f ?? 00 00 0a 7d ?? 00 00 04 06 02 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


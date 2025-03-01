rule Backdoor_MSIL_RevengeRat_GG_2147746109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RevengeRat.GG!MTB"
        threat_id = "2147746109"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 52 00 65 00 76 00 65 00 6e 00 67 00 65 00 2d 00 52 00 41 00 54 00 [0-50] 5c 00 4e 00 75 00 63 00 6c 00 65 00 61 00 72 00 20 00 45 00 78 00 70 00 6c 00 6f 00 73 00 69 00 6f 00 6e 00 5c 00 4e 00 75 00 63 00 6c 00 65 00 61 00 72 00 20 00 45 00 78 00 70 00 6c 00 6f 00 73 00 69 00 6f 00 6e 00 5c 00 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 [0-20] 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 52 65 76 65 6e 67 65 2d 52 41 54 [0-50] 5c 4e 75 63 6c 65 61 72 20 45 78 70 6c 6f 73 69 6f 6e 5c 4e 75 63 6c 65 61 72 20 45 78 70 6c 6f 73 69 6f 6e 5c 6f 62 6a 5c 44 65 62 75 67 5c [0-20] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Nuclear Explosion\\Nuclear Explosion\\obj\\Debug\\Nuclear Explosion.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_MSIL_RevengeRat_A_2147764927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RevengeRat.A!ibt"
        threat_id = "2147764927"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Revenge-RAT" wide //weight: 3
        $x_2_2 = "3.tcp.ngrok.io" wide //weight: 2
        $x_1_3 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_4 = "SELECT * FROM FirewallProduct" wide //weight: 1
        $x_1_5 = "select * from Win32_Processor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_RevengeRat_TR_2147817027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RevengeRat.TR!MTB"
        threat_id = "2147817027"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 1f 00 00 0a 0a 06 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 23 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 00 08 18 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 2b 00 11 04 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_RevengeRat_YAY_2147817512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RevengeRat.YAY!MTB"
        threat_id = "2147817512"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 06 09 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 02 16 02 8e b7 6f ?? ?? ?? 0a 13 04 11 04 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_RevengeRat_KA_2147896278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RevengeRat.KA!MTB"
        threat_id = "2147896278"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 07 8f ?? 00 00 01 25 71 ?? 00 00 01 11 0a 1f 1f 5f 62 d2 81 ?? 00 00 01 11 04 11 07 8f ?? 00 00 01 25 71 ?? 00 00 01 11 09 07 11 06 11 0a 58 59 1f 1f 5f 63 d2 60 d2 81 ?? 00 00 01 11 08 11 0a 58 13 08 11 08 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


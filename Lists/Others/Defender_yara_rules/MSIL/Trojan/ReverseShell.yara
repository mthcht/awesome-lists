rule Trojan_MSIL_ReverseShell_ARL_2147847781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ReverseShell.ARL!MTB"
        threat_id = "2147847781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 2b 2e 06 6f ?? ?? ?? 0a 8d 19 00 00 01 13 05 07 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 26 09 28 ?? ?? ?? 0a 11 05 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "RevShellAI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ReverseShell_ZJV_2147941274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ReverseShell.ZJV!MTB"
        threat_id = "2147941274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8e 69 0a 03 8d ?? 00 00 01 0b 16 0c 2b 17 00 07 08 02 08 91 7e ?? 00 00 04 08 06 5d 91 61 d2 9c 00 08 17 58 0c 08 03 fe 04 13 04 11 04 2d df 07 0d 2b 00 09 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ReverseShell_A_2147960267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ReverseShell.A!AMTB"
        threat_id = "2147960267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReverseShell"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {72 01 00 00 70 20 bb 01 00 00 73 11 00 00 0a 0c 08}  //weight: 4, accuracy: High
        $x_1_2 = {25 6f 1d 00 00 0a 72 37 00 00 70 6f 20 00 00 0a 25 6f 1d 00 00 0a 72 47 00 00 70 07 28 21 00 00 0a 6f 22 00 00 0a 25 6f 1d 00 00 0a 17 6f 23 00 00 0a 25}  //weight: 1, accuracy: High
        $x_1_3 = {25 6f 27 00 00 0a 6f 28 00 00 0a 13 07 6f 29 00 00 0a 6f 28 00 00 0a 13 08 28 13 00 00 0a 11 07 6f 14 00 00 0a 13 09 28 13 00 00 0a 11 08 6f 14 00 00 0a 13 0a 09 11 09 16 11 09 8e 69 6f 15 00 00 0a 09}  //weight: 1, accuracy: High
        $x_1_4 = "185.244.180.169" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ReverseShell_AA_2147960268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ReverseShell.AA!AMTB"
        threat_id = "2147960268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReverseShell"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {72 01 00 00 70 20 bb 01 00 00 73 10 00 00 0a 0c 08}  //weight: 4, accuracy: High
        $x_1_2 = {25 6f 1c 00 00 0a 72 37 00 00 70 6f 1f 00 00 0a 25 6f 1c 00 00 0a 72 47 00 00 70 07 28 20 00 00 0a 6f 21 00 00 0a 25 6f 1c 00 00 0a 17 6f 22 00 00 0a 25}  //weight: 1, accuracy: High
        $x_1_3 = {25 6f 26 00 00 0a 6f 27 00 00 0a 13 07 6f 28 00 00 0a 6f 27 00 00 0a 13 08 28 12 00 00 0a 11 07 6f 13 00 00 0a 13 09 28 12 00 00 0a 11 08 6f 13 00 00 0a 13 0a 09 11 09 16 11 09 8e 69 6f 14 00 00 0a 09}  //weight: 1, accuracy: High
        $x_1_4 = "188.127.227.226" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


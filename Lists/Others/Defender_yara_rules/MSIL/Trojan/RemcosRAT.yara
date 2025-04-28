rule Trojan_MSIL_RemcosRAT_RAR_2147795415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.RAR!MTB"
        threat_id = "2147795415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoadInvokeEntryPoint" ascii //weight: 1
        $x_1_2 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 47 65 74 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 4c 61 74 65 47 65 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 5a 69 70 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 50 72 6f 70 65 72 74 79 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 47 65 74 56 61 6c 75 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 4d 65 6d 6f 72 79 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_RAS_2147795416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.RAS!MTB"
        threat_id = "2147795416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 49 6e 76 6f 6b 65 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 45 6e 74 72 79 50 6f 69 6e 74 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 4c 6f 61 64 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 65 74 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 4c 61 74 65 47 65 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 5a 69 70 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 47 65 74 50 72 6f 70 65 72 74 79 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 47 65 74 56 61 6c 75 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 4d 65 6d 6f 72 79 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 49 6e 76 6f 6b 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_RPB_2147795762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.RPB!MTB"
        threat_id = "2147795762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 79 00 21 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 21 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 21 00 73 00 65 00 6d 00 62 00 6c 00 79}  //weight: 1, accuracy: High
        $x_1_2 = {4c 00 6f 00 61 00 64 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 6c 65 65 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 49 6e 76 6f 6b 65 4d 65 6d 62 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 54 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 52 65 70 6c 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 47 65 74 42 79 74 65 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NV_2147820224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NV!MTB"
        threat_id = "2147820224"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 04 07 11 04 28 ?? ?? ?? 0a 9c 00 11 04 17 58 13 04 11 04 06 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d dc}  //weight: 1, accuracy: Low
        $x_1_2 = {0d 16 13 06 2b 1a 00 09 11 06 08 11 06 08 8e 69 5d 91 03 11 06 91 61 d2 9c 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d9 09 13 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NT_2147820436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NT!MTB"
        threat_id = "2147820436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 09 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 de 07}  //weight: 1, accuracy: Low
        $x_1_2 = {1f a2 0b 09 07 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 8d 00 00 00 95 00 00 00 6d 03 00 00 92 07 00 00 4d 05 00 00 13}  //weight: 1, accuracy: High
        $x_1_3 = "SmallestEnclosingCircle.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_AH_2147823787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.AH!MTB"
        threat_id = "2147823787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 74 02 ?? ?? 1b 1e 3a 39 ?? ?? 00 26 38 20 ?? ?? 00 28 17 ?? ?? 06 72 99 ?? ?? 70 7e 08 ?? ?? 04 6f 16 ?? ?? 0a 18 3a 0d ?? ?? 00 26 38 cd ?? ?? ff 11 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 69 1e 3a 18 ?? ?? 00 26 26 26 38 0b ?? ?? 00 2a 38 fa ?? ?? ff 38 f5 ?? ?? ff 38 f0 ?? ?? ff 28 01 ?? ?? 0a 38 e7 ?? ?? ff 2d 00 02 16 02}  //weight: 1, accuracy: Low
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "HttpWebRequest" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "InvokeEvent" ascii //weight: 1
        $x_1_7 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NRY_2147840040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NRY!MTB"
        threat_id = "2147840040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 1a 00 00 0a 1a 2d 09 26 06 39 ?? 00 00 00 2b 03 0a 2b f5 28 ?? 00 00 06 28 ?? 00 00 0a 17 2d 0c 26 06 6f ?? 00 00 0a 17}  //weight: 5, accuracy: Low
        $x_1_2 = "Nufkadokfrxxyqfsvdzkbhz.Ufkkhzjktigslnqzstpqp" wide //weight: 1
        $x_1_3 = "KDE Softwares" wide //weight: 1
        $x_1_4 = "Computer Sentinel" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NRL_2147840170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NRL!MTB"
        threat_id = "2147840170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 1f 00 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 6f ?? ?? 00 0a 28 ?? ?? 00 0a 13 01 38 ?? ?? 00 00 11 01 16 11 01 8e 69 28 ?? ?? 00 06 38 ?? ?? 00 00 11 01 13 02 38 ?? ?? 00 00 dd ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = {02 28 19 00 00 0a 74 ?? ?? 00 01 6f ?? ?? 00 0a 73 ?? ?? 00 0a 13 00 6f ?? ?? 00 0a 11 00 6f ?? ?? 00 0a 38 ?? ?? 00 00 11 00 6f ?? ?? 00 0a 2a}  //weight: 5, accuracy: Low
        $x_1_3 = "Jgentidkr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NRQ_2147841599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NRQ!MTB"
        threat_id = "2147841599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 00 01 00 00 14 14 17 8d ?? ?? 00 01 25 16 08 a2}  //weight: 5, accuracy: Low
        $x_1_2 = "LkXE.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NRA_2147842958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NRA!MTB"
        threat_id = "2147842958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 73 02 00 00 0a 0c 2b 0b 28 ?? 00 00 0a 2b eb 13 04 2b eb 73 ?? 00 00 0a 0b 08 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a de 07}  //weight: 5, accuracy: Low
        $x_1_2 = "Loxad" wide //weight: 1
        $x_1_3 = "Azste" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NRA_2147842958_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NRA!MTB"
        threat_id = "2147842958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 0c 00 00 0a 13 20 11 1a 73 ?? ?? 00 0a 13 21 11 21 11 20 16 73 ?? ?? 00 0a 13 22 11 22 28 ?? ?? 00 0a 73 ?? ?? 00 0a 13 23 11 14 6f ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 13 24 11 23 6f ?? ?? 00 0a 28 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "eZYWwEJRnBprivate" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NR_2147850782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NR!MTB"
        threat_id = "2147850782"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {58 13 03 20 0e 00 00 00 fe ?? ?? 00 38 ?? ?? ?? ff 16 6a 13 00 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "Bnniydtd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NR_2147850782_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NR!MTB"
        threat_id = "2147850782"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {17 2d 06 d0 11 00 00 06 26 72 ?? 00 00 70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a 25 26 07 16 07 8e 69 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "BHHHG66" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_A_2147853202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.A!MTB"
        threat_id = "2147853202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 09 17 6f ?? 00 00 0a 09 16 6f ?? 00 00 0a 09 0b 07 28 ?? 00 00 0a 0c 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NSA_2147890298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NSA!MTB"
        threat_id = "2147890298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 58 00 00 00 11 01 28 ?? 00 00 0a 13 02 38 ?? 00 00 00 11 02 13 03 38 ?? 00 00 00 11 02 16 11 02 8e 69 28 11 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "New Quote Order" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NRC_2147890299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NRC!MTB"
        threat_id = "2147890299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 e5 00 00 0a 80 ?? ?? ?? 04 11 04 20 ?? ?? ?? 76 5a 20 ?? ?? ?? a0 61 38 ?? ?? ?? ff 00 11 04 20 ?? ?? ?? 6f 5a 20 ?? ?? ?? 9e 61 38 ?? ?? ?? ff 11 04 20 ?? ?? ?? 88 5a 20 ?? ?? ?? 4d 61}  //weight: 5, accuracy: Low
        $x_1_2 = "RandomMaker.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NRR_2147892111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NRR!MTB"
        threat_id = "2147892111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 17 00 00 04 02 17 58 91 1f 10 62 60 0a 06 7e ?? 00 00 04 02 18 58 91 1e 62 60 0a 06 7e ?? 00 00 04 02 19 58 91 60 0a 02 1a 58 fe ?? ?? 00 06 17 2f 06 7e ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "5Assembled.Program" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_NEE_2147892306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.NEE!MTB"
        threat_id = "2147892306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 14 00 00 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 06 13 00 38 ?? ?? ?? 00 dd ?? ?? ?? ff 26 38 ?? ?? ?? 00 dd ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "Njswpsg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_AC_2147900750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.AC!MTB"
        threat_id = "2147900750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Zptcs.exe" ascii //weight: 1
        $x_1_2 = "http://80.66.75.40/Brqdrur.mp4" wide //weight: 1
        $x_1_3 = {d0 0e 00 00 01 28 16 00 00 06 11 02 74 08 00 00 01 6f 09 00 00 0a 28 03 00 00 2b 72 3f 00 00 70 28 17 00 00 06 28 04 00 00 2b 6f 0c 00 00 0a 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_PD_2147905833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.PD!MTB"
        threat_id = "2147905833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 26 00 00 0a 02 0e 04 03 8e 69 6f 27 00 00 0a 0a 06 0b 2b 00 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_B_2147912633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.B!MTB"
        threat_id = "2147912633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {11 06 11 0c 1f 50 58 28 ?? ?? 00 0a 13 11 11 06 11 0c 1f 54 58 28}  //weight: 20, accuracy: Low
        $x_2_2 = "Pk/fQyUYxfovSzpjTXQTaw==" wide //weight: 2
        $x_2_3 = "6RDAE5ugIBuhU+YAtzgs0A==" wide //weight: 2
        $x_2_4 = "aqPX1U8dwu6/zJsW2wqifj9Hxco755qEYqmaG6x2tcM=" wide //weight: 2
        $x_2_5 = "fV+6DQ15duc3AxpFKXLP1HQOZ19266mQIjFBQlZ3eUY=" wide //weight: 2
        $x_2_6 = "MhHM/jqaK2QHwPNI4fVu6z9Hxco755qEYqmaG6x2tcM=" wide //weight: 2
        $x_2_7 = "x1nsq75B/ENhm01AVYFTu3QOZ19266mQIjFBQlZ3eUY=" wide //weight: 2
        $x_2_8 = "uzTtO55IA9jQpri50vDCOg==" wide //weight: 2
        $x_2_9 = "91cN5ACCkbsldtQ10JYPTFHL1e9PwIH5R3jETkgaTTA=" wide //weight: 2
        $x_2_10 = "nr56dErxzfkfwUfVUnBUlVk89TTvqKnpxgkn+LkyzJk=" wide //weight: 2
        $x_2_11 = "i9JrFHxVPzCDUQHTodrH3A==" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_2_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_RemcosRAT_SDRA_2147915637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.SDRA!MTB"
        threat_id = "2147915637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 16 5d 91 13 10 11 06 06 91 11 10 61 13 11 06 18 58 17 59 11 0a 5d 13 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_SGRG_2147917283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.SGRG!MTB"
        threat_id = "2147917283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 08 58 08 5d 13 09 07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58 20 00 02 00 00 5d 13 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_C_2147917667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.C!MTB"
        threat_id = "2147917667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\" wide //weight: 2
        $x_4_2 = "/C copy *.vbs" wide //weight: 4
        $x_2_3 = "\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_4 = "RunPE" ascii //weight: 2
        $x_2_5 = "FromBase64String" ascii //weight: 2
        $x_2_6 = "ToCharArray" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_SCPF_2147919024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.SCPF!MTB"
        threat_id = "2147919024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 11 04 6f ?? ?? ?? 0a 13 08 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 04 17 58 13 04 00 11 04 07 6f ?? ?? ?? 0a fe 04 13 09 11 09 2d cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_SPRT_2147923820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.SPRT!MTB"
        threat_id = "2147923820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 13 06}  //weight: 3, accuracy: Low
        $x_3_2 = {03 11 06 11 07 11 08 94 91 6f ?? 00 00 0a 00 00 11 08 17 58 13 08 11 08 09 19 28 ?? 00 00 0a fe 04 13 09 11 09}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_MEL_2147925578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.MEL!MTB"
        threat_id = "2147925578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 0a 07 11 0a 91 11 04 11 0b 95 61 d2 9c 11 0a 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_SYDF_2147927417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.SYDF!MTB"
        threat_id = "2147927417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 27 00 00 0a 13 18 00 11 18 17 6f ?? 00 00 0a 00 11 18 18 6f ?? 00 00 0a 00 11 18 20 00 01 00 00 6f ?? 00 00 0a 00 11 18 20 80 00 00 00 6f ?? 00 00 0a 00 11 18 11 08 11 09 6f ?? 00 00 0a 13 19 00 11 19 03 16 03 8e 69 6f ?? 00 00 0a 0b de 38}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_SZJF_2147927544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.SZJF!MTB"
        threat_id = "2147927544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 18 5d 2c 0a 02 06 07 6f ?? 00 00 0a 2b 08 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d}  //weight: 5, accuracy: Low
        $x_4_2 = {26 00 03 19 8d ?? 00 00 01 25 16 11 07 16 91 9c 25 17 11 07 17 91 9c 25 18 11 07 18 91 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_SUPD_2147930729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.SUPD!MTB"
        threat_id = "2147930729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 19 8d 84 00 00 01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2b 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_SFDA_2147936936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.SFDA!MTB"
        threat_id = "2147936936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 0f 00 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? 00 00 06 16 61 d2 9c 25 17 0f 00 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? 00 00 06 16 60 d2 9c 25 18 0f 00 28 ?? 00 00 0a 20 ff 00 00 00 5f d2 9c 13 0a 1b 13 18}  //weight: 2, accuracy: Low
        $x_1_2 = {04 19 8d 01 00 00 01 25 16 11 04 9c 25 17 11 05 9c 25 18 11 06 9c 6f ?? 00 00 0a 11 11}  //weight: 1, accuracy: Low
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RemcosRAT_WL_2147940241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemcosRAT.WL!MTB"
        threat_id = "2147940241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 08 07 61 11 08 61 13 09 08 11 07 11 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


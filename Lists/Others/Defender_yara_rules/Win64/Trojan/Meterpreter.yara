rule Trojan_Win64_Meterpreter_A_2147720175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.A"
        threat_id = "2147720175"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e}  //weight: 10, accuracy: Low
        $x_1_2 = {83 e8 05 c6 43 05 e9 89 43 06 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {c6 46 05 e9 2b c6 83 e8 05 89 46 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meterpreter_B_2147721790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.B"
        threat_id = "2147721790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ba 02 d9 c8 5f ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {41 ba 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {5d 49 be 77 73 32 5f 33 32 00 00 41 56}  //weight: 1, accuracy: High
        $x_1_4 = {41 ba ea 0f df e0 ff d5 [0-32] 41 ba 99 a5 74 61 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_B_2147721790_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.B"
        threat_id = "2147721790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 ba 02 d9 c8 5f ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {41 ba 75 6e 4d 61 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {41 ba 58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9}  //weight: 1, accuracy: High
        $x_1_5 = {5d 49 be 77 73 32 5f 33 32 00 00 41 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Meterpreter_C_2147721791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.C"
        threat_id = "2147721791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 c7 c2 6c 29 24 7e ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {49 c7 c2 05 88 9d 70 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {49 ba 95 58 bb 91 00 00 00 00 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {49 ba d3 58 9d ce 00 00 00 00 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9}  //weight: 1, accuracy: High
        $x_1_6 = {49 be 77 69 6e 68 74 74 70 00 [0-8] 49 c7 c2 4c 77 26 07 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_Meterpreter_D_2147721792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.D"
        threat_id = "2147721792"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 c7 c2 2d 06 18 7b ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {49 ba 58 a4 53 e5 00 00 00 00 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {49 ba 12 96 89 e2 00 00 00 00 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {49 c7 c2 f0 b5 a2 56 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9}  //weight: 1, accuracy: High
        $x_1_6 = {49 be 77 69 6e 69 6e 65 74 00 [0-8] 49 c7 c2 4c 77 26 07 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_Meterpreter_I_2147723086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.I!attk"
        threat_id = "2147723086"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {55 48 89 e5 48 83 ec 30 48 89 4d 10 48 8b 45 10 48 89 45 f8 48 8b 45 f8 ff d0 90 48 83 c4 30 5d c3}  //weight: 3, accuracy: High
        $x_1_2 = {00 25 63 25 63 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 69 62 67 63 6a 2d 31 36 2e 64 6c 6c 00 5f 4a 76 5f 52 65 67 69 73 74 65 72 43 6c 61 73 73 65 73}  //weight: 1, accuracy: High
        $x_1_4 = {00 65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meterpreter_J_2147723087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.J!attk"
        threat_id = "2147723087"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 48 89 e5 48 83 ec 30 48 89 4d 10 48 8b 4d 10 e8 ?? ?? ?? ?? 89 45 fc c7 45 f8 00 00 00 00 8b 45 fc 48 98 48 8d 55 f8 49 89 d1 41 b8 40 00 00 00 48 89 c2 48 8b 4d 10 48 8b 05 ?? ?? ?? ?? ff d0 48 8b 45 10 ff d0 90 48 83 c4 30 5d c3}  //weight: 3, accuracy: Low
        $x_1_2 = {00 25 63 25 63 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 69 62 67 63 6a 2d 31 36 2e 64 6c 6c 00 5f 4a 76 5f 52 65 67 69 73 74 65 72 43 6c 61 73 73 65 73}  //weight: 1, accuracy: High
        $x_1_4 = {00 65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 36 34 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meterpreter_F_2147723308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.F"
        threat_id = "2147723308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 c9 48 81 e9 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 48 bb ?? ?? ?? ?? ?? ?? ?? ?? 48 31 58 27 48 2d f8 ff ff ff e2 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_A_2147727902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.gen!A"
        threat_id = "2147727902"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 be 77 73 32 5f 33 32 00 00 41 56}  //weight: 1, accuracy: High
        $x_1_2 = {44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0}  //weight: 1, accuracy: High
        $x_1_3 = {41 ba c2 db 37 67 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {41 ba b7 e9 38 ff ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {41 ba 74 ec 3b e1 ff d5}  //weight: 1, accuracy: High
        $x_2_6 = {49 b8 63 6d 64 00 00 00 00 00 41 50 41 50 48 89 e2 57 57 57 4d 31 c0 6a 0d 59 41 50 e2 fc}  //weight: 2, accuracy: High
        $x_1_7 = {66 c7 44 24 54 01 01 48 8d 44 24 18 c6 00 68 48 89 e6 56 50 41 50 41 50 41 50 49 ff c0 41 50 49 ff c8 4d 89 c1 4c 89 c1 41 ba 79 cc 3f 86 ff d5}  //weight: 1, accuracy: High
        $x_1_8 = {bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5 48 83 c4 28 3c 06 7c 0a 80 fb e0 75 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meterpreter_A_2147727903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147727903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 be 77 73 32 5f 33 32 00 00 41}  //weight: 1, accuracy: High
        $x_1_2 = {41 ba 4c 77 26 07 ff}  //weight: 1, accuracy: High
        $x_2_3 = {4d 31 c9 49 89 f0 48 89 da 48 89 f9 41 ba 02 d9 c8 5f ff d5 48 83 c4 20 48 01 c3 48 29 c6 75 e0}  //weight: 2, accuracy: High
        $x_1_4 = {41 ba 58 a4 53 e5 ff}  //weight: 1, accuracy: High
        $x_1_5 = {41 02 1c 00 48 89 c2 80 e2 0f 02 1c 16 41 8a 14 00 41 86 14 18 41 88 14 00 fe c0 75 e3}  //weight: 1, accuracy: High
        $x_1_6 = {fe c0 41 02 1c 00 41 8a 14 00 41 86 14 18 41 88 14 00 41 02 14 18 41 8a 14 10 41 30 11 49 ff c1}  //weight: 1, accuracy: High
        $x_1_7 = {48 ff c9 75 db 5f 41 ff e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meterpreter_A_2147727903_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147727903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 0a 4c 53 75}  //weight: 1, accuracy: High
        $x_1_4 = {8e 4e 0e ec 74 [0-5] aa fc 0d 7c 74 [0-5] 54 ca af 91 74 [0-5] 1b c6 46 79 [0-5] f2 32 f6 0e 75}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 5f 28 45 33 c0 33 d2 48 83 c9 ff ?? 03 ?? ff 94 24 88 00 00 00 45 33 c0 ?? 8b ?? 41 8d ?? ?? ff d3 48 8b c3}  //weight: 1, accuracy: Low
        $x_2_6 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 [0-16] ff d6}  //weight: 2, accuracy: Low
        $x_2_7 = {3c 45 8b cb 33 c9 ?? 03 ?? 41 b8 00 30 00 00 [0-16] ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meterpreter_A_2147727903_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.A!!Meterpreter.gen!A"
        threat_id = "2147727903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "Meterpreter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 be 77 73 32 5f 33 32 00 00 41 56}  //weight: 1, accuracy: High
        $x_1_2 = {44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0}  //weight: 1, accuracy: High
        $x_1_3 = {41 ba c2 db 37 67 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {41 ba b7 e9 38 ff ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {41 ba 74 ec 3b e1 ff d5}  //weight: 1, accuracy: High
        $x_2_6 = {49 b8 63 6d 64 00 00 00 00 00 41 50 41 50 48 89 e2 57 57 57 4d 31 c0 6a 0d 59 41 50 e2 fc}  //weight: 2, accuracy: High
        $x_1_7 = {66 c7 44 24 54 01 01 48 8d 44 24 18 c6 00 68 48 89 e6 56 50 41 50 41 50 41 50 49 ff c0 41 50 49 ff c8 4d 89 c1 4c 89 c1 41 ba 79 cc 3f 86 ff d5}  //weight: 1, accuracy: High
        $x_1_8 = {bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5 48 83 c4 28 3c 06 7c 0a 80 fb e0 75 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meterpreter_B_2147729691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.gen!B"
        threat_id = "2147729691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 be 77 73 32 5f 33 32 00 00 41}  //weight: 1, accuracy: High
        $x_1_2 = {41 ba 4c 77 26 07 ff}  //weight: 1, accuracy: High
        $x_2_3 = {4d 31 c9 49 89 f0 48 89 da 48 89 f9 41 ba 02 d9 c8 5f ff d5 48 83 c4 20 48 01 c3 48 29 c6 75 e0}  //weight: 2, accuracy: High
        $x_1_4 = {41 ba 58 a4 53 e5 ff}  //weight: 1, accuracy: High
        $x_1_5 = {41 02 1c 00 48 89 c2 80 e2 0f 02 1c 16 41 8a 14 00 41 86 14 18 41 88 14 00 fe c0 75 e3}  //weight: 1, accuracy: High
        $x_1_6 = {fe c0 41 02 1c 00 41 8a 14 00 41 86 14 18 41 88 14 00 41 02 14 18 41 8a 14 10 41 30 11 49 ff c1}  //weight: 1, accuracy: High
        $x_1_7 = {48 ff c9 75 db 5f 41 ff e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meterpreter_K_2147730769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.K"
        threat_id = "2147730769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/lesnuages/hershell/meterpreter.Meterpreter" ascii //weight: 1
        $x_1_2 = "/lesnuages/hershell/meterpreter.GenerateURIChecksum" ascii //weight: 1
        $x_1_3 = "AliveKharoshthiManichaeanMessage" ascii //weight: 1
        $x_1_4 = "unixpacketunknown pcuser-agentws2_32.dll" ascii //weight: 1
        $x_1_5 = "mcachemeterpretermethodargs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Meterpreter_RDA_2147842632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.RDA!MTB"
        threat_id = "2147842632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 ec 33 45 f4 89 45 e8 8b 45 e8 c1 e8 18 88 45 bc 8b 45 e8 c1 e8 10 88 45 bd 8b 45 e8 c1 e8 08 88 45 be 8b 45 e8 88 45 bf b8 31 00 00 00 48 89 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_RPY_2147843246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.RPY!MTB"
        threat_id = "2147843246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 8a 04 3e 41 32 84 1d e8 03 00 00 48 ff c3 42 88 04 3f 49 ff c7 83 e3 0f 49 39 ef 0f 8d 1b ff ff ff 48 85 db 0f 84 68 ff ff ff 49 39 f7 7c d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_MKA_2147845384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.MKA!MTB"
        threat_id = "2147845384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b d0 49 2b c8 49 63 c1 4c 8d 1d ?? ?? ?? ?? 42 8a 04 18 32 04 11 88 02 41 8d 41 01 25 ?? ?? ?? ?? 7d 07 ff c8 83 c8 f0 ff c0 48 ff c2 44 8b c8 49 ff ca 75 d0 49 8b c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_CATR_2147846439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.CATR!MTB"
        threat_id = "2147846439"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 84 24 10 01 00 00 03 00 10 00 48 8d 94 24 e0 00 00 00 48 8b 4c 24 60 ff ?? ?? ?? ?? ?? c7 44 24 20 40 00 00 00 41 b9 00 10 00 00 41 b8 00 10 00 00 33 d2 48 8b 4c 24 58 ff ?? ?? ?? ?? ?? 48 89 44 24 50 48 c7 44 24 20 00 00 00 00 41 b9 00 10 00 00 4c 8d 05 b8 1e 00 00 48 8b 54 24 50 48 8b 4c 24 58 ff ?? ?? ?? ?? ?? 48 8b 44 24 50 48 89 84 24 d8 01 00 00 48 8d 94 24 e0 00 00 00 48 8b 4c 24 60 ff ?? ?? ?? ?? ?? 48 8b 4c 24 60 ff ?? ?? ?? ?? ?? 48 8b 4c 24 60 ff ?? ?? ?? ?? ?? 48 8b 4c 24 58 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_CRHG_2147847852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.CRHG!MTB"
        threat_id = "2147847852"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 0f b7 4a 4a 48 8b 72 50 4d 31 c9 48 31 c0 ac 3c ?? 7c ?? 2c 20 41 c1 c9 0d 41 01 c1 e2 ed}  //weight: 1, accuracy: Low
        $x_1_2 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 ?? 4c 03 4c 24 08 45 39 d1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_UNK_2147848377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.UNK!MTB"
        threat_id = "2147848377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 84 55 a4 00 00 00 8b 8d a0 00 00 00 66 33 c8 66 89 8c 55 a4 00 00 00 48 ff c2 48 83 fa 1b 72 de}  //weight: 1, accuracy: High
        $x_1_2 = {65 4c 8b 34 25 60 00 00 00 49 8b 5e 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_RPX_2147848736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.RPX!MTB"
        threat_id = "2147848736"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 50 50 c6 44 24 51 53 c6 44 24 52 51 c6 44 24 53 52 c6 44 24 54 56 c6 44 24 55 57 c6 44 24 56 55 c6 44 24 57 54 c6 44 24 58 41 c6 44 24 59 50 c6 44 24 5a 41 c6 44 24 5b 51 c6 44 24 5c 41 c6 44 24 5d 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_CCAH_2147889379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.CCAH!MTB"
        threat_id = "2147889379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 e8 48 8d 55 18 48 89 54 24 28 48 8b 55 10 48 89 54 24 20 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_SG_2147892989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.SG!MTB"
        threat_id = "2147892989"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\udemybarz.pdb" ascii //weight: 2
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "Shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_EB_2147895879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.EB!MTB"
        threat_id = "2147895879"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinSock 2.0" ascii //weight: 1
        $x_1_2 = "MPGoodStatus" ascii //weight: 1
        $x_1_3 = "ws2_32" ascii //weight: 1
        $x_1_4 = "AQAPRQVH1" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "CreateSemaphoreA" ascii //weight: 1
        $x_1_8 = "YZAXAYAZH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_PACD_2147899058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.PACD!MTB"
        threat_id = "2147899058"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 fa 15 48 0f 45 ca 41 ff c1 42 0f b6 04 11 48 8d 51 01 41 30 40 ff 41 81 f9 cc 01 00 00 72 d9}  //weight: 1, accuracy: High
        $x_1_2 = "mysuperdupersecretkey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_DA_2147906273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.DA!MTB"
        threat_id = "2147906273"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 c9 41 0f b6 54 8a 08 30 53 ff}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f b6 40 fd c1 e1 06 41 0b 0c 82 8b c1 c1 f8 10 41 88 04 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_CCIQ_2147914414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.CCIQ!MTB"
        threat_id = "2147914414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 ?? ?? 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 ?? 6e 01 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 20 00 00 00 00 41 b9 ?? ?? 00 00 4c 8d 05 ?? ?? ?? ?? 48 89 c1 48 8b 05 ?? 6e 01 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_GAD_2147939647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.GAD!MTB"
        threat_id = "2147939647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EDR_attacks_path:string" ascii //weight: 2
        $x_2_2 = "\\programdata\\Cymulate\\Agent\\AttacksLogs" ascii //weight: 2
        $x_2_3 = "source\\repos\\windows-scenarios\\Payloads\\CymulateStagelessMeterpreter\\x64\\Release\\CymulateStagelessMeterpreter.pdb" ascii //weight: 2
        $x_1_4 = "TARGETRESOURCE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meterpreter_AHB_2147947241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meterpreter.AHB!MTB"
        threat_id = "2147947241"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 85 4c 10 00 00 48 98 0f b6 84 05 f0 07 00 00 32 85 4b 10 00 00 89 c2 8b 85 4c 10 00 00 48 98 88 54 05 b0 83 85 4c 10 00 00 01 8b 85 4c 10 00 00 3d 39 08 00 00 76}  //weight: 2, accuracy: High
        $x_2_2 = {48 8d 95 e0 07 00 00 48 8b 85 48 10 00 00 48 01 d0 0f b6 00 32 85 37 10 00 00 48 8d 4d a0 48 8b 95 48 10 00 00 48 01 ca 88 02 48 83 85 48 10 00 00 01 48 81 bd 48 10 00 00 39 08 00 00 76}  //weight: 2, accuracy: High
        $x_3_3 = {b9 07 01 00 00 48 89 c7 48 89 d6 f3 48 a5 48 89 f2 48 89 f8 0f b7 0a 66 89 08 c6 85 ?? 10 00 00 42}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


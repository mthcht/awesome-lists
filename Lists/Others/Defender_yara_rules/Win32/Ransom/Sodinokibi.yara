rule Ransom_Win32_Sodinokibi_A_2147735617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.A"
        threat_id = "2147735617"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 8b da 33 f6 57 8b f9 85 db 7e 0d e8 0f fd ff ff 30 04 3e 46 3b f3 7c f3}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 3d c4 36 4f 00 75 0c 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 40 3d f2 70 86 00 7c e5 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_C_2147741043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.C"
        threat_id = "2147741043"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 0f b6 c8 89 4d fc 8a 94 0d fc fe ff ff 0f b6 c2 03 c6 0f b6 f0 8a 84 35 fc fe ff ff 88 84 0d fc fe ff ff 88 94 35 fc fe ff ff 0f b6 8c 0d fc fe ff ff 0f b6 c2 03 c8 8b 45 14 0f b6 c9 8a 8c 0d fc fe ff ff 32 0c 07 88 08 40 89 45 14 8b 45 fc 83 eb 01}  //weight: 1, accuracy: High
        $x_1_2 = "sysshadow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_E_2147741161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.E"
        threat_id = "2147741161"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KQAAAG05SW4AAAAA76wWo" ascii //weight: 1
        $x_1_2 = "ovaGogAAAAAAAAAA" ascii //weight: 1
        $x_1_3 = "imfpSwTgtZX15oQPPqWxMek0t3swq4A" ascii //weight: 1
        $x_1_4 = {40 00 8b 44 8e ?? 89 44 8f ?? 8b 44 8e ?? 89 44 8f ?? 8b 44 8e ?? 89 44 8f ?? 8b 44 8e ?? 89 44 8f ?? 8b 44 8e ?? 89 44 8f ?? 8b 44 8e ?? 89 44 8f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Sodinokibi_2147741179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi"
        threat_id = "2147741179"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DisableRealtimeMonitoring $true" wide //weight: 10
        $x_1_2 = "\\kworking\\agent.exe" wide //weight: 1
        $x_1_3 = "agent.crt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Sodinokibi_F_2147741307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.F"
        threat_id = "2147741307"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 70 64 62 [0-32] 5c 74 6d 70 5f 0a 00 5c 62 69 6e 5c [0-21] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_PA_2147741555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.PA!MTB"
        threat_id = "2147741555"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IQAhACAARABBAE4ARwBFAFIAIAAhACEAIQANAAoARABPAE4AVAAgAHQAcgB5ACAAdABvACAAYwBoAGEAbgBnAGUAIABmAGkAbABlAHMAIABiAHkAIAB5AG8AdQByAHMAZQBsAGYALAAgAEQATwBOAFQAIAB1AHMAZQAgAGEAbgB5ACAAdABoAGkAcgBkACAAcABhAHIAdAB5ACAAcwBvAGYAdAB3AGEAcgBlACAAZgBvAHI" ascii //weight: 1
        $x_1_2 = "AIAByAGUAcwB0AG8AcgBpAG4AZwAgAHkAbwB1AHIAIABkAGEAdABhACAAbwByACAAYQBuAHQAaQB2AGkAcgB1AHMAIABzAG8AbAB1AHQAaQBvAG4AcwAgAC0AIABpAHQAcwAgAG0AYQB5ACAAZQBuAHQAYQBpAGwAIABkAGEAbQBnAGUAIABvAGYAIAB0AGgAZQAgAHAAcgBpAHYAYQB0AGUAIABrAGUAeQAgAGEAbgBkAC" ascii //weight: 1
        $x_1_3 = "QQBsAGwAIABvAGYAIAB5AG8AdQByACAAZgBpAGwAZQBzACAAYQByAGUAIABlAG4AYwByAHkAcAB0AGUAZAAhAA0ACgANAAoARgBpAG4AZAAgAHsARQBYAFQAfQAtAHIAZQBhAGQAbQBlAC4AdAB4AHQAIABhAG4AZAAgAGYAbwBsAGwAbwB3ACAAaQBuAHMAdAB1AGMAdABpAG8AbgBzAAAA" ascii //weight: 1
        $x_1_4 = "sophos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_AB_2147742227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.AB"
        threat_id = "2147742227"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IQAhACAARABBAE4ARwBFAFIAIAAhACEAIQANAAoARABPAE4AVAAgAHQAcgB5ACAAdABvACAAYwBoAGEAbgBnAGUAIABmAGkAbABlAHMAIABiAHkAIAB5AG8AdQByAHMAZQBsAGYALAAgAEQATwBOAFQAIAB1AHMAZQAgAGEAbgB5ACAAdABoAGkAcgBkACAAcABhAHIAdAB5ACAAcwBvAGYAdAB3AGEAcgBlACAAZgBvAHI" ascii //weight: 1
        $x_1_2 = "AIAByAGUAcwB0AG8AcgBpAG4AZwAgAHkAbwB1AHIAIABkAGEAdABhACAAbwByACAAYQBuAHQAaQB2AGkAcgB1AHMAIABzAG8AbAB1AHQAaQBvAG4AcwAgAC0AIABpAHQAcwAgAG0AYQB5ACAAZQBuAHQAYQBpAGwAIABkAGEAbQBnAGUAIABvAGYAIAB0AGgAZQAgAHAAcgBpAHYAYQB0AGUAIABrAGUAeQAgAGEAbgBkAC" ascii //weight: 1
        $x_1_3 = "{EXT}-readme.txt\",\"exp\":false,\"img\":" ascii //weight: 1
        $x_1_4 = "BsAGUALgAgAFkAbwB1ACAAYwBhAG4AIABjAGgAZQBjAGsAIABpAHQAOgAgAGEAbABsACAAZgBpAGwAZQBzACAAbwBuACAAeQBvAHUAcgAgAHMAeQBzAHQAZQBtACAAaABhAHMAIABlAHgAdABlAG4AcwBpAG8AbgAgAHsARQBYAFQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Sodinokibi_SA_2147742450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.SA"
        threat_id = "2147742450"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTIS" ascii //weight: 1
        $x_1_2 = "MODLIS" ascii //weight: 1
        $x_1_3 = "mpsvc.dll" ascii //weight: 1
        $x_1_4 = "MsMpEng.exe" ascii //weight: 1
        $x_5_5 = {ba 88 55 0c 00 a3 ?? ?? ?? ?? ?? ?? e8 [0-32] ba d0 56 00 00 c7 ?? ?? ?? ?? ?? ?? e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Sodinokibi_SA_2147742450_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.SA"
        threat_id = "2147742450"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c0 01 47 30 11 4f 34 01 57 30 8b 57 78 8b c2 11 77 34 8b 77 7c 8b ce 0f a4 c1 04 c1 e0 04 01 47 28 8b c2 11 4f 2c 8b ce 0f a4 c1 01 03 c0 01 47 28 11 4f 2c 01 57 28 8b 57 70 8b c2 11 77 2c 8b 77 74 8b ce 0f a4 c1 04 c1 e0 04 01 47 20 8b c2 11 4f 24 8b ce 0f a4 c1 01 03 c0 01 47 20 11 4f 24 01 57 20 8b 57 68 8b c2 11 77 24 8b 77 6c 8b ce 0f a4 c1 04 c1 e0 04 01 47 18 8b c2 11 4f 1c 8b ce 0f a4 c1 01 03 c0 01 47 18 11 4f 1c 01 57 18 8b 57 60 8b c2 11 77 1c 8b 77 64}  //weight: 1, accuracy: High
        $x_1_2 = "expand 32-byte kexpand 16-byte k" ascii //weight: 1
        $x_1_3 = {f7 6f 38 03 c8 8b 43 48 13 f2 f7 6f 20 03 c8 8b 43 38 13 f2 f7 6f 30 03 c8 8b 43 40 13 f2 f7 6f 28 03 c8 8b 43 28 13 f2 f7 6f 40 03 c8 8b 45 08 13 f2 89 48 68 89 70 6c 8b 43 38 f7 6f 38 8b c8 8b f2 8b 43 28 f7 6f 48 03 c8 13 f2 8b 43 48 f7 6f 28 03 c8 8b 43 30 13 f2 f7 6f 40 0f a4 ce 01 03 c9 03 c8 8b 43 40 13 f2 f7 6f 30 03 c8 8b 45 08 13 f2 89 48 70 89 70 74 8b 43 38 f7 6f 40 8b c8}  //weight: 1, accuracy: High
        $x_1_4 = {33 c0 8b 5a 68 8b 52 6c 0f a4 fe 08 c1 e9 18 0b c6 c1 e7 08 8b 75 08 0b cf 89 4e 68 8b ca 89 46 6c 33 c0 8b 7e 60 8b 76 64 0f a4 da 19 c1 e9 07 0b c2 c1 e3 19 8b 55 08 0b cb 89 4a 60 8b cf 89 42 64 33 c0 8b 5a 10 8b 52 14 0f ac f7 15 c1 e1 0b c1 ee 15 0b c7 0b ce 8b 75}  //weight: 1, accuracy: High
        $x_1_5 = {c1 01 c1 ee 1f 0b d1 03 c0 0b f0 8b c2 33 43 24 8b ce 33 4b 20 33 4d e4 33 45 e0 89 4b 20 8b cb 8b 5d e0 89 41 24 8b ce 33 4d e4 8b c2 31 4f 48 33 c3 8b cf 31 41 4c 8b c7 8b ce 33 48 70 8b c2 33 47 74 33 4d e4 33 c3 89 4f 70 8b cf 89 41 74 8b}  //weight: 1, accuracy: High
        $x_1_6 = {8b 43 40 f7 6f 08 03 c8 8b 03 13 f2 f7 6f 48 03 c8 8b 43 48 13 f2 f7 2f 03 c8 8b 43 08 13 f2 f7 6f 40 03 c8 8b 43 30 13 f2 f7 6f 18 03 c8 8b 43 18 13 f2 f7 6f 30 03 c8 8b 43 38 13 f2 f7 6f 10 03 c8 8b 43 10 13 f2 f7 6f 38 03 c8 8b 43 28 13 f2}  //weight: 1, accuracy: High
        $x_1_7 = {8b ce 33 4d f8 8b c2 33 c3 31 4f 18 8b cf 31 41 1c 8b c7 8b ce 33 48 40 8b c2 33 4d f8 33 47 44 89 4f 40 33 c3 8b cf 89 41 44 8b c7 8b ce 33 48 68 8b c2 33 47 6c 33 4d f8 33 c3 89 4f 68 8b cf 89 41 6c 8b ce 8b}  //weight: 1, accuracy: High
        $x_1_8 = {36 7d 49 30 85 35 c2 c3 68 60 4b 4b 7a be 83 53 ab e6 8e 42 f9 c6 62 a5 d0 6a ad c6 f1 7d f6 1d 79 cd 20 fc e7 3e e1 b8 1a 43 38 12 c1 56 28 1a 04 c9 22 55 e0 d7 08 bb 9f 0b 1f 1c b9 13 06 35}  //weight: 1, accuracy: High
        $x_1_9 = {c2 c1 ee 03 8b 55 08 0b ce 89 4a 4c 8b cf 89 42 48 33 c0 8b 72 30 8b 52 34 c1 e9 0c 0f a4 df 14 0b c7 c1 e3 14 8b 7d 08 0b cb 89 4f 30 8b ce 89 47 34 33 c0 c1 e1 0c 0f ac d6 14 0b c6 c1 ea 14 89 47 08 0b ca}  //weight: 1, accuracy: High
        $x_1_10 = {8b f2 8b 43 38 f7 6f 28 03 c8 8b 43 18 13 f2 f7 6f 48 03 c8 8b 43 28 13 f2 f7 6f 38 03 c8 8b 43 40 13 f2 f7 6f 20 0f a4 ce 01 03 c9 03 c8 8b 43 20 13 f2 f7 6f 40 03 c8 8b 43 30 13 f2 f7 6f 30 03 c8}  //weight: 1, accuracy: High
        $x_1_11 = {33 45 fc 31 4b 28 8b cb 31 41 2c 8b ce 8b c3 33 48 50 8b c2 33 43 54 33 cf 33 45 fc 89 4b 50 8b cb 89 41 54 8b ce 8b c3 33 48 78 8b c2 33 43 7c 33 cf 33 45 fc 89 4b 78 8b cb 89 41 7c 33 b1 a0}  //weight: 1, accuracy: High
        $x_1_12 = {52 24 0f a4 fe 0e c1 e9 12 0b c6 c1 e7 0e 8b 75 08 0b cf 89 4e 20 8b ca 89 46 24 33 c0 8b 7e 78 8b 76 7c 0f a4 da 1b c1 e9 05 0b c2 c1 e3 1b 8b 55 08 0b cb 89 4a 78 8b cf 89 42 7c 33 c0 8b 9a}  //weight: 1, accuracy: High
        $x_1_13 = {f2 8b 43 38 f7 6f 20 03 c8 8b 43 40 13 f2 f7 6f 18 03 c8 8b 43 10 13 f2 f7 6f 48 03 c8 8b 43 28 13 f2 f7 6f 30 03 c8 8b 43 20 13 f2 f7 6f 38 03 c8 8b 43 30 13 f2 f7 6f 28 03 c8 8b 43 48 13 f2}  //weight: 1, accuracy: High
        $x_1_14 = {8b 47 30 13 f2 f7 6f 40 03 c8 13 f2 0f a4 ce 01 89 73 74 03 c9 89 4b 70 8b 47 30 f7 6f 48 8b c8 8b f2 8b 47 38 f7 6f 40 03 c8 13 f2 0f a4 ce 01 89 73 7c 03 c9 89 4b 78 8b 47 38 f7 6f 48 8b c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_S_2147745544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.S!MSR"
        threat_id = "2147745544"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QQBsAGwAIABvAGYAIAB5AG8AdQByACAAZgBpAGwAZQBzACAAYQByAGUAIABlAG4AYwByAHkAcAB0AGUAZAAhAA0" ascii //weight: 1
        $x_1_2 = "tor browser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_2147749350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi!MTB"
        threat_id = "2147749350"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enc_read" ascii //weight: 1
        $x_1_2 = "enc_worker" ascii //weight: 1
        $x_1_3 = "start IOCP worker" wide //weight: 1
        $x_1_4 = "end IOCP worker" wide //weight: 1
        $x_1_5 = "wipe folders" wide //weight: 1
        $x_1_6 = "start encrypt files" wide //weight: 1
        $x_1_7 = "kill process" wide //weight: 1
        $x_1_8 = "knock stat domain" wide //weight: 1
        $x_1_9 = "k!!! IS RU !!!" wide //weight: 1
        $x_1_10 = "manual UAC b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_RAA_2147755318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.RAA!MTB"
        threat_id = "2147755318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 3b fd ff ff 8b 4c 24 04 30 04 0e b8 01 00 00 00 29 44 24 04 83 7c 24 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 00 8d 54 24 ?? 52 6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 25 ff 00 00 00 81 3d ?? ?? ?? ?? 21 06 00 00 a3 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Sodinokibi_G_2147756777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.G!MSR"
        threat_id = "2147756777"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QQBsAGwAIABvAGYAIAB5AG8AdQByACAAZgBpAGwAZQBzACAAYQByAGUAIABlAG4AYwByAHkAcAB0AGUAZAAhAA0ACgANAAoARgBpAG4AZAAgAHsARQBYAFQAfQAtAHIAZQBhAGQAbQBlAC4AdAB4AHQAIABhAG4AZAAgAGYAbwBsAGwAbwB3ACAAaQBuAHMAdAB1AGMAdABpAG8AbgBzAAAA" ascii //weight: 1
        $x_1_2 = "LQAtAC0APQA9AD0AIABXAGUAbABjAG8AbQBlAC4AIABBAGcAYQBpAG4ALgAgAD0APQA9AC0ALQAtAA0ACgANAAoAWwArAF0AIABXAGgAYQB0AHMAIABIAGEAcABwAGUAbgA" ascii //weight: 1
        $x_1_3 = "AcgB5AHQAaABpAG4AZwAgAGYAbwByACAAcgBlAHMAdABvAHIAaQBuAGcALAAgAGIAdQB0ACAAcABsAGUAYQBzAGUAIABzAGgAbwB1AGwAZAAgAG4AbwB0ACAAaQBuAHQAZQByAGYAZQByAGUALgANAAoAIQAhACEAIAAhACEAIQAgACEAIQAhAAAA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Sodinokibi_DSA_2147757549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.DSA!MTB"
        threat_id = "2147757549"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 8c 0d fc fe ff ff 0f b6 c2 03 c8 8b 45 14 0f b6 c9 8a 8c 0d fc fe ff ff 32 0c 07 88 08 40 89 45 14 8b 45 fc 83 eb 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_DSB_2147757550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.DSB!MTB"
        threat_id = "2147757550"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 02 8b 55 0c 0f b6 c9 03 c8 0f b6 c1 8b 4d 08 8a 04 08 32 04 1a 88 03 43 8b 45 10 89 5d 14 83 ef 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_SK_2147760158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.SK!MSR"
        threat_id = "2147760158"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 8b d0 d3 e2 8b c8 c1 e9 05 03 4d d8 03 55 dc 89 35 ?? ?? ?? 00 33 d1 8b 4d f0 03 c8 33 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_TA_2147768139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.TA"
        threat_id = "2147768139"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 50 0c 83 c2 14 [0-32] 8b 7d 08 81 f7 ?? ?? ?? ?? 8b 59 28 6a 2b 58 89 45 fc 0f b7 33 66 85 f6 [0-16] 8d 46 bf 8d 5b 02 66 83 f8 19 77 03 83 ce 20 69 d2 0f 01 00 00 0f b7 c6 0f b7 33 03 d0 66 85 f6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_AD_2147779016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.AD!MTB"
        threat_id = "2147779016"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec e9 07 00 55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 ?? ac}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Sodinokibi_A_2147780281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.A!!Sodinokibi.A"
        threat_id = "2147780281"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "Sodinokibi: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 8a 1c 39 33 d2 0f b6 cb f7 75 10 8b 45 0c 0f b6 04 02 03 c6 03 c8 0f b6 f1 8b 4d fc 8a 04 3e 88 04 39 41 88 1c 3e 89 4d fc 81 f9 00 01 00 00 72 cd}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 40 0f b6 c8 8b 45 08 89 4d 10 8b 5d 10 8a 0c 01 0f b6 c1 03 c6 0f b6 f0 8b 45 08 8a 04 06 88 04 13 8b c2 8b d3 8b 5d 14 88 0c 06}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 04 02 8b 55 0c 0f b6 c9 03 c8 0f b6 c1 8b 4d 08 8a 04 08 32 04 1a 88 03 43 8b 45 10 89 5d 14 83 ef 01 75 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_B_2147780282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.B!!Sodinokibi.B"
        threat_id = "2147780282"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "Sodinokibi: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 06 4a 6a 08 33 c8 46 5f 8b c1 d1 e9 83 e0 01 f7 d0 40 25 20 83 b8 ed 33 c8 83 ef 01 75 ea 85 d2 75 dc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 6a 2b 58 eb 0c 69 c0 0f 01 00 00 42 0f b6 c9 03 c1 8a 0a 84 c9 75 ee}  //weight: 1, accuracy: High
        $x_1_3 = {05 02 00 00 80 33 c9 53 0f a2 8b f3 5b 8d 5d e8 89 03 8b 45 fc 89 73 04 40 89 4b 08 8b f3 89 53 0c 89 45 fc a5 a5 a5 a5 8b 7d f8 83 c7 10 89 7d f8 83 f8 03 7c ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_C_2147780283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.C!!Sodinokibi.C"
        threat_id = "2147780283"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        info = "Sodinokibi: an internal category used to refer to some threats"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 81 f7 ?? ?? ?? ?? 8b 59 28 6a 2b 58 89 45 fc 0f b7 33 66 85 f6 74 2d 8b d0 8d 46 bf 8d 5b 02 66 83 f8 19 77 03 83 ce 20 69 d2 0f 01 00 00 0f b7 c6 0f b7 33 03 d0 66 85 f6 75 de 89 55 fc 8b 55 f8 8b 45 fc 3b c7 74 0f 8b 09 3b ca 75 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_SB_2147783804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.SB"
        threat_id = "2147783804"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ServiceCrtMain" ascii //weight: 1
        $x_1_2 = {55 8b ec 83 ec 08 68 00 01 00 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 fc 89 45 f0 8b 4d ?? 83 c1 ?? 89 4d ?? 81 7d f0 ff 00 00 00 77 1f ba 01 00 00 00 6b c2 00 8b 4d ?? 0f b6 ?? ?? 33 55 ?? 89 55 ?? 83 7d f4 24 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_SB_2147783804_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.SB"
        threat_id = "2147783804"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "expand 32-byte kexpand 16-byte k" ascii //weight: 1
        $x_1_2 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 41 00 63 00 74 00 69 00 76 00 65 00 2c 01 01 09 30 2d 39 41 2d 5a 61 2d 7a 02 00 2c 01 01 09 30 2d 39 41 2d 5a 61 2d 7a}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateThread" ascii //weight: 1
        $x_1_4 = "GetExitCodeProcess" ascii //weight: 1
        $x_1_5 = "CloseHandle" ascii //weight: 1
        $x_1_6 = "SetErrorMode" ascii //weight: 1
        $x_1_7 = ":!:(:/:6:C:\\:m:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_SC_2147913043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.SC"
        threat_id = "2147913043"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 85 f6 74 25 8b 55 08 83 66 04 00 89 3e 8b 0a 0b 4a 04 14 00 59}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f8 89 75 fc 50 8d 45 fc 89 75 f8 50 56 56 6a 01 6a 30}  //weight: 1, accuracy: High
        $x_1_3 = {75 0c 72 d3 33 c0 40 5f 5e 5b 8b e5 5d c3 33 c0 eb f5 55 8b ec 83}  //weight: 1, accuracy: High
        $x_1_4 = {0c 8b 04 b0 83 78 04 05 75 1c ff 70 08 ff 70 0c ff 75 0c ff}  //weight: 1, accuracy: High
        $x_1_5 = {fb 8b 45 fc 50 8b 08 ff 51 08 5e 8b c7 5f 5b 8b e5 5d c3 55}  //weight: 1, accuracy: High
        $x_1_6 = {33 d2 8b 4d f4 8b f1 8b 45 f0 0f a4 c1 01 c1 ee 1f 15 00 bc 00 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {54 8b ce f7 d1 8b c2 23 4d dc f7 d0 33 4d f4 23 c7 33 45 e8 89}  //weight: 1, accuracy: High
        $x_1_8 = {0c 89 46 0c 85 c0 75 2a 33 c0 eb 6c 8b 46 08 85 c0 74 62 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_Sodinokibi_SD_2147913044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.SD"
        threat_id = "2147913044"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 0f b6 c8 89 4d fc 8a 94 0d fc fe ff ff 0f b6 c2 03 c6 0f b6 f0 8a 84 35 fc fe ff ff 88 84 0d fc fe ff ff 88 94 35 fc fe ff ff 0f b6 8c 0d fc fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 c2 03 c8 8b 45 14 0f b6 c9 8a 8c 0d fc fe ff ff 32 0c 07 88 08 40 89 45 14 8b 45 fc 83 eb 01 75 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sodinokibi_SE_2147913045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sodinokibi.SE"
        threat_id = "2147913045"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 4f 1c 83 c7 20 d1 f8 83 e8 01 89 45 0c e9 ?? ?? ?? ?? 8b 75 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 8d b5 68 ff ff ff 83 c4 14 0e 00 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e8 01 eb 07 b0 0a 5d c3 83 e8 62 74 28}  //weight: 1, accuracy: High
        $x_1_4 = {8d 85 10 ff ff ff 50 8d 85 60 ff ff ff 50 8d 45 b0 50 e8}  //weight: 1, accuracy: High
        $x_1_5 = {ff 75 0c 8d 45 b0 50 8d 85 c0 fe ff ff 50}  //weight: 1, accuracy: High
        $x_1_6 = {8b 45 08 8b 40 4c 89 45 f0 8b 45 e8 89 4b 28 f7 d0 23 c2}  //weight: 1, accuracy: High
        $x_1_7 = {33 4d e0 8b 40 48 8b 5d 08 89 45 ec 8b 45 08}  //weight: 1, accuracy: High
        $x_1_8 = {ff 75 20 e8 ?? ?? ?? ?? 8d 85 80 fe ff ff 50 ff 75 24}  //weight: 1, accuracy: Low
        $x_1_9 = {89 75 d8 0f b6 45 ff 0b c8 8b c1 89 4d d8}  //weight: 1, accuracy: High
        $x_1_10 = {83 e8 13 0f 84 61 06 00 00 83 e8 3d 0f 84 fa 02 00 00 f6 c2 04 74 11 80 f9 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}


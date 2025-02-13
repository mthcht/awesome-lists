rule Ransom_Win32_Spora_A_2147719448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spora.A"
        threat_id = "2147719448"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spora"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6a 59 58 0f b7 d0 2b cb 8b c2 c1 e2 10 0b c2 d1 e9 f3 ab 13 c9 66 f3 ab}  //weight: 3, accuracy: High
        $x_2_2 = "%s\\%s.LST" wide //weight: 2
        $x_2_3 = "%s\\%s.KEY" wide //weight: 2
        $x_1_4 = "8x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.exe" wide //weight: 1
        $x_2_5 = "vssadmin.exe delete shadows" wide //weight: 2
        $x_2_6 = "bcdedit.exe /set {default} recoveryenabled no" wide //weight: 2
        $x_1_7 = "wmic.exe" wide //weight: 1
        $x_2_8 = {00 7b 64 61 74 61 7d 00 00 7b 6b 65 79 7d 00}  //weight: 2, accuracy: High
        $x_1_9 = "IsShortcut" wide //weight: 1
        $x_1_10 = "SOFTWARE\\Classes\\lnkfile" wide //weight: 1
        $x_2_11 = {2e 00 37 00 7a 00 00 00 2e 00 72 00 61 00 72 00 00 00 00 00 2e 00 7a 00 69 00 70 00 00 00 00 00 2e 00 74 00 69 00 66 00 66 00 00 00 2e 00 6a 00 70 00 65 00 67 00 00 00 2e 00 6a 00 70 00 67 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Spora_A_2147719998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spora.A!!Spora.gen!rsm"
        threat_id = "2147719998"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spora"
        severity = "Critical"
        info = "Spora: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6a 59 58 0f b7 d0 2b cb 8b c2 c1 e2 10 0b c2 d1 e9 f3 ab 13 c9 66 f3 ab}  //weight: 3, accuracy: High
        $x_2_2 = "%s\\%s.LST" wide //weight: 2
        $x_2_3 = "%s\\%s.KEY" wide //weight: 2
        $x_1_4 = "8x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.exe" wide //weight: 1
        $x_2_5 = "vssadmin.exe delete shadows" wide //weight: 2
        $x_2_6 = "bcdedit.exe /set {default} recoveryenabled no" wide //weight: 2
        $x_1_7 = "wmic.exe" wide //weight: 1
        $x_2_8 = {00 7b 64 61 74 61 7d 00 00 7b 6b 65 79 7d 00}  //weight: 2, accuracy: High
        $x_1_9 = "IsShortcut" wide //weight: 1
        $x_1_10 = "SOFTWARE\\Classes\\lnkfile" wide //weight: 1
        $x_2_11 = {2e 00 37 00 7a 00 00 00 2e 00 72 00 61 00 72 00 00 00 00 00 2e 00 7a 00 69 00 70 00 00 00 00 00 2e 00 74 00 69 00 66 00 66 00 00 00 2e 00 6a 00 70 00 65 00 67 00 00 00 2e 00 6a 00 70 00 67 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Spora_B_2147721499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spora.B"
        threat_id = "2147721499"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spora"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<hta:application windowstate=\"minimize\"/><script>new ActiveXObject(\"WScript.Shell\").Run(\"cmd /c \\\"\\\"\"+window.l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Spora_B_2147721499_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spora.B"
        threat_id = "2147721499"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spora"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\HELP_%s.html" ascii //weight: 1
        $x_2_2 = "process call create \"cmd.exe /c vssadmin.exe delete shadows" ascii //weight: 2
        $x_2_3 = "PG1ldGEgaHR0cC1lcXVpdj0ncmVmcmVzaCcgY29udGVudD0nMDsgdXJsPWh0dHA6Ly8" ascii //weight: 2
        $x_2_4 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYEYkIZivftqlhZCLdPcGwu4/MAHwbsB965BHJ120L9G1tmynAPpZc" ascii //weight: 2
        $x_1_5 = {00 25 75 3b 25 75 3b 25 75 3b 25 75 3b 25 75 3b 25 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 31 33 38 36 32 44 33 33 30 38 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 25 30 32 68 75 2e 25 30 32 68 75 2e 25 30 34 68 75 3b 00}  //weight: 1, accuracy: High
        $x_2_8 = {6b f6 12 81 c6 00 10 00 00 eb 10 f7 f1 8b f0 c1 ee 02 6b f6 12 81 c6 00 02 00 00 c1 ee 04 c1 e6 04 6a 02 53 68 7c ff ff ff ff 75 70 ff 15}  //weight: 2, accuracy: High
        $x_1_9 = {83 7d 6c 04 0f 85 ?? ?? ?? ?? 57 8d 45 ?? 50 53 ff 15 ?? ?? ?? ?? 3b 45 ?? 0f 84 ?? ?? ?? ?? 39 5d ?? 75 07 8b 45 ?? 3b c6 72 05 89 75 ?? eb 06 83 e0 e0}  //weight: 1, accuracy: Low
        $x_1_10 = {68 10 66 00 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 50 53 6a 08 53 ff 75 ?? 89 7d ?? ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 1, accuracy: Low
        $x_2_11 = {05 86 00 00 00 50 6a 40 ff 15 ?? ?? ?? ?? 8b f0 3b f3 0f 84 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6a 02}  //weight: 2, accuracy: Low
        $x_2_12 = {f6 c3 01 74 ?? 6a 3a 8d 46 ?? 66 89 45 f0 58 ff 75 10 66 89 45 f2 ff 75 0c 33 c0 66 89 45 f4 8d 45 f0 50 ff 15 ?? ?? ?? ?? 50 8d 45 f0 50 ff 55 08 d1 eb 46 83 fe 1a 72}  //weight: 2, accuracy: Low
        $x_1_13 = {8d 77 14 f6 46 f8 02 74 0b 8d 46 ec 50 e8 ?? ?? ff ff eb ?? 83 7e f0 01 75}  //weight: 1, accuracy: Low
        $x_1_14 = {6a 06 56 ff 75 08 ff d7 8d 45 f8 50 56 56 53 ff 15 ?? ?? ?? ?? 50 53 ff 35 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_2_15 = {68 00 02 00 00 ff 15 ?? ?? ?? ?? 46 83 fe 20 72 ?? eb 07 c7 45 fc 01 00 00 00 ff 75 ?? ff d7 53 ff d7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Spora_B_2147721506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spora.B!!Spora.gen!rsm"
        threat_id = "2147721506"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spora"
        severity = "Critical"
        info = "Spora: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\HELP_%s.html" ascii //weight: 1
        $x_2_2 = "process call create \"cmd.exe /c vssadmin.exe delete shadows" ascii //weight: 2
        $x_2_3 = "PG1ldGEgaHR0cC1lcXVpdj0ncmVmcmVzaCcgY29udGVudD0nMDsgdXJsPWh0dHA6Ly8" ascii //weight: 2
        $x_2_4 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYEYkIZivftqlhZCLdPcGwu4/MAHwbsB965BHJ120L9G1tmynAPpZc" ascii //weight: 2
        $x_1_5 = {00 25 75 3b 25 75 3b 25 75 3b 25 75 3b 25 75 3b 25 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 31 33 38 36 32 44 33 33 30 38 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 25 30 32 68 75 2e 25 30 32 68 75 2e 25 30 34 68 75 3b 00}  //weight: 1, accuracy: High
        $x_2_8 = {6b f6 12 81 c6 00 10 00 00 eb 10 f7 f1 8b f0 c1 ee 02 6b f6 12 81 c6 00 02 00 00 c1 ee 04 c1 e6 04 6a 02 53 68 7c ff ff ff ff 75 70 ff 15}  //weight: 2, accuracy: High
        $x_1_9 = {83 7d 6c 04 0f 85 ?? ?? ?? ?? 57 8d 45 ?? 50 53 ff 15 ?? ?? ?? ?? 3b 45 ?? 0f 84 ?? ?? ?? ?? 39 5d ?? 75 07 8b 45 ?? 3b c6 72 05 89 75 ?? eb 06 83 e0 e0}  //weight: 1, accuracy: Low
        $x_1_10 = {68 10 66 00 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 50 53 6a 08 53 ff 75 ?? 89 7d ?? ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 1, accuracy: Low
        $x_2_11 = {05 86 00 00 00 50 6a 40 ff 15 ?? ?? ?? ?? 8b f0 3b f3 0f 84 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6a 02}  //weight: 2, accuracy: Low
        $x_2_12 = {f6 c3 01 74 ?? 6a 3a 8d 46 ?? 66 89 45 f0 58 ff 75 10 66 89 45 f2 ff 75 0c 33 c0 66 89 45 f4 8d 45 f0 50 ff 15 ?? ?? ?? ?? 50 8d 45 f0 50 ff 55 08 d1 eb 46 83 fe 1a 72}  //weight: 2, accuracy: Low
        $x_1_13 = {8d 77 14 f6 46 f8 02 74 0b 8d 46 ec 50 e8 ?? ?? ff ff eb ?? 83 7e f0 01 75}  //weight: 1, accuracy: Low
        $x_1_14 = {6a 06 56 ff 75 08 ff d7 8d 45 f8 50 56 56 53 ff 15 ?? ?? ?? ?? 50 53 ff 35 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_2_15 = {68 00 02 00 00 ff 15 ?? ?? ?? ?? 46 83 fe 20 72 ?? eb 07 c7 45 fc 01 00 00 00 ff 75 ?? ff d7 53 ff d7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Spora_C_2147727889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spora.C!bit"
        threat_id = "2147727889"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spora"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 56 8b 75 08 57 8b 7d 0c e8 70 ff ff ff 30 04 3e 5f 5e 5d c2 08 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 81 e1 ff 00 00 00 56 8b 34 8d ?? ?? 00 01 03 c6 25 ff 00 00 00 8a 14 85 ?? ?? 00 01 0f b6 d2}  //weight: 1, accuracy: Low
        $x_1_3 = {00 01 89 14 8d ?? ?? 00 01 89 0d ?? ?? 00 01 8b 0c 85 ?? ?? 00 01 03 ca 81 e1 ff 00 00 00 a3 ?? ?? 00 01 8a 04 8d ?? ?? 00 01 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Spora_MA_2147847383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spora.MA!MTB"
        threat_id = "2147847383"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spora"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All Your Files Encrypted To Decryption Email Us" wide //weight: 1
        $x_1_2 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_3 = "schtasks /delete /tn Microsoft_Auto_Scheduler" ascii //weight: 1
        $x_1_4 = "\\Restore_Your_Files.txt" ascii //weight: 1
        $x_1_5 = "_Encryption_Mode:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


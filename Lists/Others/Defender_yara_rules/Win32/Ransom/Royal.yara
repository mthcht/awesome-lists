rule Ransom_Win32_Royal_A_2147834341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.A"
        threat_id = "2147834341"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 00 2e 00 72 00 6f 00 79 00 61 00 6c 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = "delete shadow" wide //weight: 3
        $x_1_3 = "$windows.~ws" wide //weight: 1
        $x_1_4 = "$windows.~bt" wide //weight: 1
        $x_1_5 = "$windows.old" wide //weight: 1
        $x_1_6 = "README.TXT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Royal_A_2147834342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.A!dha"
        threat_id = "2147834342"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = ".royal" wide //weight: 1
        $x_1_3 = "tor browser" wide //weight: 1
        $x_1_4 = "AES for x86, CRYPTOGAMS by <appro@openssl.org>" ascii //weight: 1
        $x_1_5 = "README.TXT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Royal_MP_2147834708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.MP!MTB"
        threat_id = "2147834708"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 45 ff 8b 4d 08 03 4d f8 0f b6 11 33 d0 8b 45 08 03 45 f8 88 10 0f b6 4d f0 8b 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Royal_ZZ_2147834906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.ZZ"
        threat_id = "2147834906"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {89 00 89 40 04 89 [0-6] 8d [0-6] 50 68 02 02 00 00 ff 15 ?? ?? ?? ?? 6a 00 6a 01 6a 02 ff 15 ?? ?? ?? ?? 8b ?? 83 ?? ff 74 ?? 6a 00 6a 00 8d [0-3] c7 [0-3] b9 07 a2 25 50 6a 04 8d [0-6] c7 [0-3] f3 dd 60 46 50 6a 10 8d [0-3] c7 [0-3] 8e e9 76 e5 50 68 06 00 00 c8 ?? c7 [0-3] 8c 74 06 3e ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 10, accuracy: Low
        $x_10_3 = {08 02 00 00 00 0f 57 c0 02 00 c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 ?? ff ff ff ff 8d ?? 20 c7 ?? e4 00 00 00 00 0f 11 ?? cc c7 ?? dc 00 00 00 00 83 ?? 01 75 d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Royal_C_2147834980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.C!dha"
        threat_id = "2147834980"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".royal" wide //weight: 1
        $x_1_2 = "tor browser" wide //weight: 1
        $x_1_3 = "README.TXT" wide //weight: 1
        $x_1_4 = "$windows.~ws" wide //weight: 1
        $x_1_5 = "$recycle.bin" wide //weight: 1
        $x_1_6 = "ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Royal_RPS_2147835038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.RPS!MTB"
        threat_id = "2147835038"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 55 0c 73 27 8b 45 08 03 45 f4 0f b6 08 8b 45 f4 99 be ?? ?? ?? ?? f7 fe 8b 45 fc 0f b6 14 10 33 ca 8b 45 f8 03 45 f4 88 08 eb c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Royal_RPT_2147835039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.RPT!MTB"
        threat_id = "2147835039"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README.TXT" wide //weight: 1
        $x_1_2 = ".royal" wide //weight: 1
        $x_1_3 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_4 = "C:\\Windows\\System32\\vssadmin.exe" wide //weight: 1
        $x_1_5 = "-path" wide //weight: 1
        $x_1_6 = "GetLogicalDrives" ascii //weight: 1
        $x_1_7 = "FindFirstFileW" ascii //weight: 1
        $x_1_8 = "FindNextFileW" ascii //weight: 1
        $x_1_9 = "WriteFile" ascii //weight: 1
        $x_1_10 = "CryptAcquireContextW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Royal_PA_2147835251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.PA!MTB"
        threat_id = "2147835251"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 8d 84 24 [0-4] 66 0f 13 44 24 ?? 50 68 [0-4] 66 0f 13 84 24 [0-4] 66 0f 13 84 24 [0-4] 66 0f 13 84 24 [0-4] 66 0f 13 84 24 [0-4] 0f 29 44 24 ?? ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 84 24 a0 47 00 00 50 ff 15 [0-4] 83 f8 20 74 ?? 6a 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_3 = {85 c0 0f 85 [0-4] 8b 8f [0-4] b8 ab aa aa 2a 8b b7 [0-4] 2b ce ff 45 ?? 83 45 d0 ?? f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 39 45 ?? 8b 45 ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Royal_PAB_2147848669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.PAB!MTB"
        threat_id = "2147848669"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 02 6b c2 0d 8b d6 2b d0 0f b6 44 95 bc 30 47 02 b8 ?? ?? ?? ?? 8b 55 e8 8d 14 17 f7 e2 8d 7f 06 c1 ea 02 6b c2 0d 2b f0 0f b6 44 b5 ?? 30 47 fd 8d 04 1f 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Royal_SA_2147913039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Royal.SA"
        threat_id = "2147913039"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Royal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ".royal_" wide //weight: 5
        $x_5_2 = "royal_dll.dll" ascii //weight: 5
        $x_2_3 = "README.TXT" wide //weight: 2
        $x_2_4 = "-networkonly" wide //weight: 2
        $x_2_5 = "-localonly" wide //weight: 2
        $x_5_6 = "If you are reading this, it means that your system were hit by Royal ransomware." ascii //weight: 5
        $x_5_7 = "Try Royal today and enter the new era of data security!" ascii //weight: 5
        $x_5_8 = "http://royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion/" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}


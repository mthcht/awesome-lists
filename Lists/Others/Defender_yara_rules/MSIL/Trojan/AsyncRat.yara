rule Trojan_MSIL_AsyncRat_MK_2147784756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MK!MTB"
        threat_id = "2147784756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_2_2 = {47 00 65 00 74 00 53 00 70 00 65 00 63 00 69 00 61 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 [0-5] 20 00 26 00 20 00 22 00 5c 00 [0-5] 2e 00 78 00 6d 00 6c 00 22 00}  //weight: 2, accuracy: Low
        $x_2_3 = {47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 [0-5] 20 26 20 22 5c [0-5] 2e 78 6d 6c 22}  //weight: 2, accuracy: Low
        $x_2_4 = "Set object_Shell = CreateObject(\"Shell.Application\")" ascii //weight: 2
        $x_2_5 = {6f 00 62 00 6a 00 65 00 63 00 74 00 5f 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 22 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 22 00 2c 00 20 00 [0-16] 2c 00 20 00 22 00 22 00 2c 00 20 00 22 00 22 00 2c 00}  //weight: 2, accuracy: Low
        $x_2_6 = {6f 62 6a 65 63 74 5f 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 4d 53 42 75 69 6c 64 2e 65 78 65 22 2c 20 [0-16] 2c 20 22 22 2c 20 22 22 2c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRat_MA_2147796703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MA!MTB"
        threat_id = "2147796703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 05 00 00 04 72 43 00 00 70 7e 23 00 00 0a 6f 24 00 00 0a 28 05 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MA_2147796703_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MA!MTB"
        threat_id = "2147796703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gnirtS46esaBmorF" ascii //weight: 1
        $x_1_2 = "trevnoC.metsyS" ascii //weight: 1
        $x_1_3 = "YXZ1234567890" ascii //weight: 1
        $x_1_4 = "VidyaGame" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
        $x_1_6 = "I--n--v--o--k--e" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MA_2147796703_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MA!MTB"
        threat_id = "2147796703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 20 03 11 1e 11 20 16 11 20 8e 69 28 ?? ?? ?? 0a 00 09 7b ?? ?? ?? 04 11 0c 11 1c 58 11 20 11 20 8e 69 12 00 28 ?? ?? ?? 06 16 fe 01 13 21 11 21 2c 06}  //weight: 1, accuracy: Low
        $x_1_2 = "://45.147.230.71" wide //weight: 1
        $x_1_3 = "GetThreadContext" ascii //weight: 1
        $x_1_4 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "ResumeThread" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MB_2147796706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MB!MTB"
        threat_id = "2147796706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 02 6f ?? ?? ?? 0a 17 59 0c 2b 18 00 06 07 93 0d 06 07 06 08 93 9d 06 08 09 9d 00 07 17 58 0b 08 17 59 0c 07 08 fe 04 13 04 11 04 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "GetTypes" ascii //weight: 1
        $x_1_3 = "SetWinEventHook" ascii //weight: 1
        $x_1_4 = "GetTaskbarState" ascii //weight: 1
        $x_1_5 = "FromBase64CharArray" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "get_MousePosition" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MC_2147796709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MC!MTB"
        threat_id = "2147796709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BE545252-B020-4BEF-8C57-5ACE5AF7632E" ascii //weight: 1
        $x_1_2 = "DuckyReload" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "get_Key" ascii //weight: 1
        $x_1_6 = "BCryptDestroyKey" ascii //weight: 1
        $x_1_7 = "BCryptImportKey" ascii //weight: 1
        $x_1_8 = "BCryptEncrypt" ascii //weight: 1
        $x_1_9 = "Replace" ascii //weight: 1
        $x_1_10 = "GZipStream" ascii //weight: 1
        $x_1_11 = "ToArray" ascii //weight: 1
        $x_1_12 = "MemoryStream" ascii //weight: 1
        $x_1_13 = "CompressionMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MD_2147796710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MD!MTB"
        threat_id = "2147796710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "43F9DE27-A430-4E4C-8879-D5B00AE8A184" ascii //weight: 1
        $x_1_3 = "ShUuJPQEYMoFXQof" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MD_2147796710_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MD!MTB"
        threat_id = "2147796710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateDecryptor" ascii //weight: 1
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "Cryptography" ascii //weight: 1
        $x_1_4 = "CipherMode" ascii //weight: 1
        $x_1_5 = "Qrtqxxasegcyxzkf" ascii //weight: 1
        $x_1_6 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_7 = "set_Key" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ME_2147797053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ME!MTB"
        threat_id = "2147797053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://ufile.io/rftaeqtc" ascii //weight: 1
        $x_1_2 = "JNKNAIWUFH8" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "GetResponse" ascii //weight: 1
        $x_1_6 = "WebResponse" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "Encoding" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
        $x_1_10 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MF_2147797971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MF!MTB"
        threat_id = "2147797971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateDecryptor" ascii //weight: 1
        $x_1_2 = "Slyyjunpedmffrueabrnwbzm" ascii //weight: 1
        $x_1_3 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_4 = "Cryptography" ascii //weight: 1
        $x_1_5 = "CipherMode" ascii //weight: 1
        $x_1_6 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_7 = "set_Key" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MI_2147811903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MI!MTB"
        threat_id = "2147811903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 06 6f ?? ?? ?? 0a 8e 69 8d ?? 00 00 01 0c 06 6f ?? ?? ?? 0a 8e 69 8d ?? 00 00 01 0d 07 08 16 08 8e 69 6f ?? ?? ?? 0a 26 07 09 16 09 8e 69 6f ?? ?? ?? 0a 26 06 08 09 6f ?? ?? ?? 0a 13 04 07 11 04 16 73 ?? 00 00 0a 13 05 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 59 d4 8d ?? 00 00 01 13 06 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 26 11 06 13 07 de 2c 11 05 2c 07 11 05 6f ?? ?? ?? 0a dc 11 04 2c 07 11 04 6f ?? ?? ?? 0a dc}  //weight: 1, accuracy: Low
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "IsAdmin" ascii //weight: 1
        $x_1_4 = "PreventSleep" ascii //weight: 1
        $x_1_5 = "Kill" ascii //weight: 1
        $x_1_6 = "StrReverse" ascii //weight: 1
        $x_1_7 = "RunAntiAnalysis" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
        $x_1_11 = "Decrypt" ascii //weight: 1
        $x_1_12 = "FromBase64String" ascii //weight: 1
        $x_1_13 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPE_2147825426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPE!MTB"
        threat_id = "2147825426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 72 01 00 00 70 28 ?? 00 00 0a 2d 31 11 04 72 05 00 00 70 28 ?? 00 00 0a 2d 60 11 04 72 0b 00 00 70 28 ?? 00 00 0a 3a cf 00 00 00 11 04 72 0f 00 00 70 28 ?? 00 00 0a 3a 0b 01 00 00 2a 72 09 00 00 70 0a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPL_2147829757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPL!MTB"
        threat_id = "2147829757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 05 09 11 05 09 8e 69 5d 91 06 11 05 91 61 d2 9c 11 05 17 58 16 2d 04 13 05 11 05 06 8e 69 32 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NE_2147831124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NE!MTB"
        threat_id = "2147831124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 08 2c 58 1c 13 0f ?? ?? ff ff ff 08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NE_2147831124_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NE!MTB"
        threat_id = "2147831124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 15 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 58 0b 72 ?? 00 00 70 12 01 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Flappy_Bird_Windows_Form" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NE_2147831124_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NE!MTB"
        threat_id = "2147831124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AzdoKRAcNcuslkWpjtBB" ascii //weight: 4
        $x_4_2 = "JwKYRfbVGjrKfTivNrFq" ascii //weight: 4
        $x_3_3 = "W3fascacaxc" ascii //weight: 3
        $x_3_4 = "crypted.exe" ascii //weight: 3
        $x_3_5 = "Debugger Detected" wide //weight: 3
        $x_2_6 = "Lominers" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_WFC_2147831291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.WFC!MTB"
        threat_id = "2147831291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 91 0d 06 72 c6 0a 00 70 09 8c 0b 00 00 01 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEA_2147831456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEA!MTB"
        threat_id = "2147831456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "m9OIO8Q0EK" ascii //weight: 5
        $x_5_2 = "pZbnhv6YB" ascii //weight: 5
        $x_5_3 = "sqkpikos.pdb" ascii //weight: 5
        $x_5_4 = "kLjw4iIs" ascii //weight: 5
        $x_4_5 = "62E6F13B53D67FDD780" ascii //weight: 4
        $x_4_6 = "4D697520997BC3" ascii //weight: 4
        $x_3_7 = "set_CreateNoWindow" ascii //weight: 3
        $x_1_8 = "VirtualProtectEx" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "GetCurrentProcess" ascii //weight: 1
        $x_1_11 = "OpenProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NED_2147831771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NED!MTB"
        threat_id = "2147831771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 04 11 05 16 11 06 6f 15 00 00 0a 11 04 6f 16 00 00 0a 09 11 05 16 20 a0 28 00 00 6f 17 00 00 0a 25 13 06 16 30 d9}  //weight: 5, accuracy: High
        $x_5_2 = {7e 01 00 00 04 28 0d 00 00 06 28 07 00 00 0a 2a}  //weight: 5, accuracy: High
        $x_5_3 = "MAINTHREADClASS" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEF_2147831833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEF!MTB"
        threat_id = "2147831833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 06 02 09 6f 19 00 00 0a 11 06 58 11 04 59 1f 1a 28 04 00 00 06 11 04 58 d1 13 07 06 12 07 28 20 00 00 0a 28 21 00 00 0a 0a 2b 1b}  //weight: 5, accuracy: High
        $x_5_2 = "avyhk" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEH_2147831834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEH!MTB"
        threat_id = "2147831834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 07 09 07 8e 69 5d 91 03 09 91 61 d2 9c 09 17 58 0d 09 16}  //weight: 5, accuracy: High
        $x_5_2 = {28 17 00 00 0a 2b e6 28 05 00 00 06 2b e1 6f 18 00 00 0a 2b dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEG_2147832046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEG!MTB"
        threat_id = "2147832046"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6f 0d 00 00 0a a4 0b 00 00 01 11 12 28 0e 00 00 0a 6f 0f 00 00 0a 11 08 11 09 11 0a 28 10 00 00 0a}  //weight: 5, accuracy: High
        $x_3_2 = "gHCkKUi" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEI_2147832047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEI!MTB"
        threat_id = "2147832047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 2f 00 00 0a 06 28 30 00 00 0a 6f 31 00 00 0a 72 ?? ?? 00 70 6f 32 00 00 0a 72 ?? ?? 00 70 6f 33 00 00 0a}  //weight: 5, accuracy: Low
        $x_4_2 = "C:\\ProgramData\\Done.vbs" wide //weight: 4
        $x_4_3 = "RegAsm.exe" wide //weight: 4
        $x_4_4 = "powershell.exe" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEJ_2147832260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEJ!MTB"
        threat_id = "2147832260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "fassssssfdsssssdgsaddasafxassssssss" ascii //weight: 5
        $x_5_2 = "Prtrssddddddsddsfrfdrfdsffffffffssram" ascii //weight: 5
        $x_5_3 = "DeleteDiffffffffffrectory" ascii //weight: 5
        $x_5_4 = "WDE1uqwIJQPyatszns3FPw==" wide //weight: 5
        $x_5_5 = "uJ5WL2SFMcPUWLNyJNa07OblUwraNaEK7XWMSfEF0aw=" wide //weight: 5
        $x_2_6 = "Directory you waggggggggnt to delete is not exist" wide //weight: 2
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEK_2147832261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEK!MTB"
        threat_id = "2147832261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 2b 16 02 07 8f ?? 00 00 01 25 47 06 07 1f 10 5d 91 61 d2 52 07 17 58 0b 07 02 8e 69 32 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEL_2147832293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEL!MTB"
        threat_id = "2147832293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$26e0a7d6-dd59-47d0-92b4-5219ad185e38" ascii //weight: 5
        $x_5_2 = "yf6IWFNzSEerSO9Z5Gx" ascii //weight: 5
        $x_2_3 = "logs_quick_" wide //weight: 2
        $x_2_4 = "runningProcessesTool" wide //weight: 2
        $x_2_5 = "HCS Computers & Laptops" ascii //weight: 2
        $x_2_6 = "processor_graph_container" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEM_2147832382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEM!MTB"
        threat_id = "2147832382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 28 0b 00 00 06 28 3a 00 00 0a 00 07 28 38 00 00 0a 26 00 2b 1c}  //weight: 5, accuracy: High
        $x_4_2 = "backdor2" wide //weight: 4
        $x_4_3 = "C:\\Documents and Settings\\All Users\\Application Data\\dllhost.exe" wide //weight: 4
        $x_4_4 = "WpfApp1.exe" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEN_2147832826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEN!MTB"
        threat_id = "2147832826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 28 0b 00 00 0a 06 28 0c 00 00 0a 6f 0d 00 00 0a 6f 0e 00 00 0a 72 01 00 00 70 14 6f 0f 00 00 0a 26 2a}  //weight: 5, accuracy: High
        $x_4_2 = "VQobcRXIh6R9UHKHRx" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEP_2147832924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEP!MTB"
        threat_id = "2147832924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0a 13 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEO_2147833294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEO!MTB"
        threat_id = "2147833294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 6f 16 00 00 0a 0d 00 09 28 17 00 00 0a 03 28 18 00 00 0a 1f 1e 5d 5b 28 19 00 00 0a 13 05 12 05 28 1a 00 00 0a 13 04 06 11 04 6f 1b 00 00 0a 26 00 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAA_2147834189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAA!MTB"
        threat_id = "2147834189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 09 00 00 06 06 fe 06 18 00 00 06 73 18 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAB_2147834397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAB!MTB"
        threat_id = "2147834397"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 09 11 05 09 6f 18 00 00 0a 1e 5b 6f 16 00 00 0a 6f 19 00 00 0a 00 09 17 6f 1a 00 00 0a 00 08 09 6f 1b 00 00 0a 17}  //weight: 10, accuracy: High
        $x_5_2 = {00 11 06 02 16 02 8e 69 6f 1d 00 00 0a 00 11 06 6f 1e 00 00 0a 00 00 de 14}  //weight: 5, accuracy: High
        $x_5_3 = "QzpcV2luZG93c1xNaWNyb3NvZnQuTkVUXEZyYW1ld29ya1x2NC4wLjMwMzE5XFJlZ0FzbS5leGU=" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAD_2147835137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAD!MTB"
        threat_id = "2147835137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 01 2a 02 28 17 00 00 0a 28 14 00 00 06 28 18 00 00 0a 73 19 00 00 0a 13 00}  //weight: 5, accuracy: High
        $x_2_2 = "cdn.discordapp.com" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAG_2147835621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAG!MTB"
        threat_id = "2147835621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 03 00 00 0a 0a 06 72 01 00 00 70 6f 04 00 00 0a 06 72 17 00 00 70 6f 05 00 00 0a 06 17 6f 06 00 00 0a 06 17 6f 07 00 00 0a 06 28 08 00 00 0a 26 2a}  //weight: 10, accuracy: High
        $x_2_2 = "powershell" wide //weight: 2
        $x_2_3 = "EncodedCommand" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAH_2147835622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAH!MTB"
        threat_id = "2147835622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b 00 06 1e 2e 14 2b 18 03 04 5d 0c 2b 16 03 04 5a 0c 2b 10 03 04 61 0c 2b 0a 03 04 58 0c 2b 04 03 0c 2b 00 08 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAI_2147835623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAI!MTB"
        threat_id = "2147835623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0c 06 08 28 ?? 00 00 0a 7e ?? 00 00 04 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f ?? 00 00 0a 0b de 11 de 0f}  //weight: 10, accuracy: Low
        $x_2_2 = "WScript.Shell" wide //weight: 2
        $x_2_3 = "cmstp.exe" wide //weight: 2
        $x_2_4 = "powershell.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABCZ_2147835710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABCZ!MTB"
        threat_id = "2147835710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 08 07 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 50 16 02 50 8e 69 6f ?? ?? ?? 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "rZLTYnaGFJbYQDyoMXZmWPSfdSKDNtpAPQeEwXBK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAJ_2147835723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAJ!MTB"
        threat_id = "2147835723"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 00 06 72 01 00 00 70 7d 03 00 00 04 06 28 0a 00 00 06 06 fe 06 0c 00 00 06 73 0b 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 7d 04 00 00 04 06 fe 06 0d 00 00 06 73 0e 00 00 0a 28 03 00 00 2b 6f 10 00 00 0a 0b 07 0c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAK_2147835724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAK!MTB"
        threat_id = "2147835724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Venom RAT" ascii //weight: 5
        $x_5_2 = "Client.Install" ascii //weight: 5
        $x_5_3 = "AgentsExhausted" ascii //weight: 5
        $x_5_4 = "CHmFdDgJkJIj" ascii //weight: 5
        $x_2_5 = "Antivirus" ascii //weight: 2
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAM_2147835902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAM!MTB"
        threat_id = "2147835902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 00 70 1f 2d 28 28 00 00 06 28 12 00 00 0a 02 18 16 8d 01 00 00 01 28 13 00 00 0a 0a 20 66 08 00 00 28 14 00 00 0a 06 2a}  //weight: 10, accuracy: High
        $x_5_2 = "In+v+++++++++++o++++++++++++++++++++++++++++++++++k" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABDY_2147835935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABDY!MTB"
        threat_id = "2147835935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 09 11 05 08 02 11 05 18 5a 18 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 9c 06 6f ?? ?? ?? 0a 2d db de 0d 06 2c 06 06 6f ?? ?? ?? 0a 17 2c f4 dc}  //weight: 2, accuracy: Low
        $x_1_2 = "GetDomain" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "CreateDelegate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAN_2147836320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAN!MTB"
        threat_id = "2147836320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 24 11 05 06 8f ?? 00 00 01 25 71 ?? 00 00 01 06 0e 04 58 20 ?? 00 00 00 5f d2 61 d2 81 ?? 00 00 01 06 17 58 0a 06 04 32 d8}  //weight: 10, accuracy: Low
        $x_5_2 = "SEZNAM_STEAM" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAO_2147836321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAO!MTB"
        threat_id = "2147836321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "195.2.79.233" wide //weight: 10
        $x_5_2 = "System.Windows.Forms" ascii //weight: 5
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "System.Reflection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAP_2147836371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAP!MTB"
        threat_id = "2147836371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 03 7d ?? 00 00 04 06 04 7d ?? 00 00 04 00 02 06 fe 06 ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 ?? 00 00 0a 0b 2b 00 07 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "2121a2121m2121s2121i2121.2121d2121l2121l2121" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAQ_2147836372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAQ!MTB"
        threat_id = "2147836372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 02 16 9a 0a 02 17 9a 74 ?? 00 00 01 0b 02 18 9a a5 ?? 00 00 01 0c 02 19 9a 74 ?? 00 00 1b 0d 06 07 08 09 28 ?? 00 00 0a 13 04 2b 00 11 04 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "2020a2020m2020s2020i2020.2020d2020l2020l2020" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAR_2147836512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAR!MTB"
        threat_id = "2147836512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 28 08 00 00 06 0a 28 07 00 00 06 0b 06 28 09 00 00 0a 00 07 28 09 00 00 0a 00 06 28 0a 00 00 0a}  //weight: 10, accuracy: High
        $x_5_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAS_2147836971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAS!MTB"
        threat_id = "2147836971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 80 0a 00 00 04 28 ?? 00 00 0a 80 07 00 00 04 28 0d 00 00 06 7e 09 00 00 04 6f ?? 00 00 0a 7e 08 00 00 04 6f ?? 00 00 0a 0a 7e 08 00 00 04 6f ?? 00 00 0a 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "%BATCHNAME%" wide //weight: 2
        $x_2_3 = "B.text" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAT_2147836976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAT!MTB"
        threat_id = "2147836976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 0a 00 00 0a 0a 06 72 01 00 00 70 6f 0b 00 00 0a 06 72 17 00 00 70 6f 0c 00 00 0a 06 17 6f 0d 00 00 0a 06 17 6f 0e 00 00 0a 06 28 0f 00 00 0a 26 2a}  //weight: 10, accuracy: High
        $x_2_2 = "powershell" wide //weight: 2
        $x_2_3 = "-EncodedCommand" wide //weight: 2
        $x_2_4 = "set_CreateNoWindow" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAU_2147837072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAU!MTB"
        threat_id = "2147837072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "get_BHAUZ7WHAZ" ascii //weight: 3
        $x_3_2 = "get_OZIA8HAZI" ascii //weight: 3
        $x_3_3 = "cabae4ee6e3a1a97a860b9dce88516381" ascii //weight: 3
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABGI_2147837429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABGI!MTB"
        threat_id = "2147837429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 24 00 00 04 18 9a 28 38 00 00 0a 7e 25 00 00 04 28 38 00 00 0a 28 24 01 00 06 28 8d 00 00 06 28 51 00 00 0a 80 26 00 00 04 20 0c 00 00 00 28 af 00 00 06 3a 13 ff ff ff 26 20 08 00 00 00 38 08 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "ProgramFile.StartUP.resources" wide //weight: 1
        $x_1_3 = "ProgramFile.Resources.resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAV_2147837659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAV!MTB"
        threat_id = "2147837659"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a2 25 18 09 a2 25 19 17 8c ?? 00 00 01 a2 13 04 14 13 05 07 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = "hedefimbelli" wide //weight: 5
        $x_5_3 = "aHR0cHM6Ly9vbmUubGl0ZXNoYXJlLmNvL2Rvd25sb2FkLnBocD9pZD1QSDA0S1RU" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AG_2147838188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AG!MTB"
        threat_id = "2147838188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 07 11 04 8f 15 00 00 01 72 77 00 00 70 28 ?? ?? ?? 0a a2 11 04 17 58 13 04 11 04 6a 08 6e 32 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAW_2147838268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAW!MTB"
        threat_id = "2147838268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 04 06 7e 43 00 00 04 06 91 20 d0 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 43 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 5, accuracy: High
        $x_2_2 = "DownloadData" wide //weight: 2
        $x_2_3 = "scorda" wide //weight: 2
        $x_2_4 = "Ajouter un stagiaire" wide //weight: 2
        $x_2_5 = "System.Reflection.Assembly" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAX_2147839075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAX!MTB"
        threat_id = "2147839075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 2c 0b 02 6f 1f 00 00 0a 17 5f 17 33 06 73 20 00 00 0a 7a 73 21 00 00 0a 0a 16 0b 2b 1c 02 07 18 6f 22 00 00 0a 0c 06 08 1f 10 28 23 00 00 0a 6f 24 00 00 0a 26 07 18 58 0b 07 02 6f 1f 00 00 0a 32 db}  //weight: 10, accuracy: High
        $x_5_2 = "tutorial.gya" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAY_2147839127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAY!MTB"
        threat_id = "2147839127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 30 00 00 0a 0a 06 28 31 00 00 0a 03 50 6f 32 00 00 0a 6f 33 00 00 0a 0b 73 34 00 00 0a 0c 08 07 6f 35 00 00 0a 08 18 6f 36 00 00 0a 08 6f 37 00 00 0a 02 50 16 02 50 8e 69 6f 38 00 00 0a 2a}  //weight: 10, accuracy: High
        $x_5_2 = "setUTCMinutesTU Jurassic.Library.JSFunctionFlags" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEAZ_2147839265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEAZ!MTB"
        threat_id = "2147839265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 00 06 18 6f 52 00 00 0a 00 06 18 6f 53 00 00 0a 00 06 6f 54 00 00 0a 0b 07 02 16 02 8e 69 6f 55 00 00 0a 0c 08 0d de 0b}  //weight: 10, accuracy: High
        $x_1_2 = "calc_pro.Form1.resources" ascii //weight: 1
        $x_1_3 = "StayAway_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBA_2147839871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBA!MTB"
        threat_id = "2147839871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 2c 00 00 0a 0a 06 17 6f 2d 00 00 0a 06 18 6f 2e 00 00 0a 06 03 04 6f 2f 00 00 0a 0b 07 02 16 02 8e 69 6f 30 00 00 0a 0c 07 6f 31 00 00 0a 06 6f 32 00 00 0a 08 2a}  //weight: 10, accuracy: High
        $x_2_2 = "payload.exe" ascii //weight: 2
        $x_2_3 = "amsi.dll" wide //weight: 2
        $x_2_4 = "VirtualProtect" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBB_2147839878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBB!MTB"
        threat_id = "2147839878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 08 28 31 00 00 0a 7e 0a 00 00 04 6f 32 00 00 0a 6f 33 00 00 0a 6f 34 00 00 0a 06 18 6f 35 00 00 0a 06 6f 36 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 37 00 00 0a 0b de 11}  //weight: 10, accuracy: High
        $x_2_2 = "get_Computer" ascii //weight: 2
        $x_2_3 = "AES_Decryptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPM_2147840847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPM!MTB"
        threat_id = "2147840847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "powershell.exe -WindowStyle hidden -nop -exec bypass" wide //weight: 1
        $x_1_3 = "New-Object Net.WebClient" wide //weight: 1
        $x_1_4 = "DownloadString" wide //weight: 1
        $x_1_5 = "4.227.228.46" wide //weight: 1
        $x_1_6 = "admin/12.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBC_2147841115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBC!MTB"
        threat_id = "2147841115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "64d78a83-9274-4cd8-9dc8-e5f76f09ba37" ascii //weight: 5
        $x_4_2 = "d2luZHdvcyQ=" wide //weight: 4
        $x_4_3 = "Dotfuscated\\windwos.pdb" ascii //weight: 4
        $x_2_4 = "windwos.My" ascii //weight: 2
        $x_2_5 = "GetPixel" ascii //weight: 2
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_7 = "RPF:SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBD_2147841214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBD!MTB"
        threat_id = "2147841214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {25 26 17 da 0c 16 0d 2b 24 7e 0b 00 00 04 07 09 16 6f 3c 00 00 0a 25 26 13 04 12 04 28 3d 00 00 0a 25 26 6f 3e 00 00 0a 00 09 17 d6 0d 09 08 31 d8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABJU_2147841601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABJU!MTB"
        threat_id = "2147841601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f ?? ?? ?? 0a 0b de 11 de 0f 3d 00 06 08 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBG_2147841886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBG!MTB"
        threat_id = "2147841886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 53 00 00 0a 6f 55 00 00 0a 06 07 6f 56 00 00 0a 17 73 37 00 00 0a 0c 08 02 16 02 8e 69 6f 57 00 00 0a 08}  //weight: 10, accuracy: High
        $x_2_2 = "WindowsFormsApp1.Properties.Resources" wide //weight: 2
        $x_2_3 = "RPF:SmartAssembly" ascii //weight: 2
        $x_2_4 = "RijndaelManaged" ascii //weight: 2
        $x_2_5 = "WriteProcessMemory" ascii //weight: 2
        $x_2_6 = "CreateDecryptor" ascii //weight: 2
        $x_2_7 = "$$method0x6000023-1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBI_2147841893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBI!MTB"
        threat_id = "2147841893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 06 6f ?? 00 00 0a 00 11 04 05 6f ?? 00 00 0a 00 11 04 0e 04 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 03 16 03 8e b7 6f ?? 00 00 0a 0b 11 04 6f ?? 00 00 0a 00 07 0c 2b 00 08 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "md5Decrypt" ascii //weight: 2
        $x_2_3 = "set_ShutdownStyle" ascii //weight: 2
        $x_2_4 = "ProcessHacker" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABKE_2147841911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABKE!MTB"
        threat_id = "2147841911"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 07 09 16 6f ?? ?? ?? 0a 13 04 12 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 d6 0d 09 08 3e}  //weight: 2, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CND_2147842011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CND!MTB"
        threat_id = "2147842011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 9a 0d 7e ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 2d 12 7e ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 2c 25 17 0a 02 2c}  //weight: 5, accuracy: Low
        $x_1_2 = "ollydbg" ascii //weight: 1
        $x_1_3 = "idaw64" ascii //weight: 1
        $x_1_4 = "x64dbg" ascii //weight: 1
        $x_1_5 = "windbg" ascii //weight: 1
        $x_1_6 = "dnSpy" ascii //weight: 1
        $x_1_7 = "SELECT * FROM Win32_Processor" ascii //weight: 1
        $x_1_8 = "Select * From Win32_ComputerSystem" ascii //weight: 1
        $x_1_9 = "Select * from Win32_Processor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_DAV_2147842019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.DAV!MTB"
        threat_id = "2147842019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? 00 06 04 08 18 58 17 59 04 8e 69 5d 91 59 20}  //weight: 3, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBH_2147842024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBH!MTB"
        threat_id = "2147842024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Dotfuscated\\CryptoObfuscator_Output\\v4.pdb" ascii //weight: 5
        $x_2_2 = "cc5d78b89af81b43173c0546a1d2e65a6" ascii //weight: 2
        $x_2_3 = "ca604132458de59347dc06bcbb1fd7bf3" ascii //weight: 2
        $x_2_4 = "v4.Resources.resources" ascii //weight: 2
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CLP_2147842128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CLP!MTB"
        threat_id = "2147842128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0b 11 0c 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 11 07 07 6e 11 0c 6a 58 1a 6a 5d d4 91 61 d2 81 ?? ?? ?? ?? 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBF_2147842136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBF!MTB"
        threat_id = "2147842136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "0bef987d-128a-42fa-94c7-e4a24bd0c86a" ascii //weight: 5
        $x_2_2 = "forestnurse" wide //weight: 2
        $x_2_3 = "enzyme" wide //weight: 2
        $x_2_4 = "IDMPATCH" ascii //weight: 2
        $x_1_5 = "pbDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AYR_2147843422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AYR!MTB"
        threat_id = "2147843422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 04 09 6f 26 00 00 0a 13 05 06 12 05 28 27 00 00 0a 6f 28 00 00 0a 26 00 11 04 17 58 13 04 11 04 07 fe 02 16 fe 01 13 06 11 06 2d d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AYR_2147843422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AYR!MTB"
        threat_id = "2147843422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 08 00 00 04 11 09 7e 07 00 00 04 11 09 91 7e 09 00 00 04 11 09 7e 09 00 00 04 8e 69 5d 91 61 d2 9c 11 07 28 ?? ?? ?? 0a 00 00 11 0a 17 58 13 0a 11 0a 7e 07 00 00 04 8e 69 fe 04 13 0b 11 0b 2d a7}  //weight: 2, accuracy: Low
        $x_1_2 = "NoPower" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AYR_2147843422_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AYR!MTB"
        threat_id = "2147843422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "linkpicture.com/q/converted_101.png" wide //weight: 2
        $x_1_2 = "OpenRead" wide //weight: 1
        $x_1_3 = "windwos.pdb" ascii //weight: 1
        $x_1_4 = "This assembly is protected by an unregistered version of IntelliLock" wide //weight: 1
        $x_1_5 = "windwos.exe" wide //weight: 1
        $x_1_6 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_NEBK_2147844170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.NEBK!MTB"
        threat_id = "2147844170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ferergretfdgrt45y45y45y45yrtgrg" ascii //weight: 5
        $x_5_2 = "petrolmanagementsystem.Supplier_withdraw_pump_bank_detail.resources" ascii //weight: 5
        $x_1_3 = "RPF:SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABNL_2147845031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABNL!MTB"
        threat_id = "2147845031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 07 09 16 6f ?? ?? ?? 0a 13 04 12 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 d6 0d 09 08 31 dc 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 26 de 10}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "Bitmap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABTX_2147846305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABTX!MTB"
        threat_id = "2147846305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f 00 08 20 00 04 00 00 58 28 ?? 00 00 2b 07 02 08 20 00 04 00 00 20 7c 01 00 00 20 78 01 00 00 28 ?? 00 00 06 0d 1b 13 0d 38 ?? ?? ?? ff 1b 13 06 1f 0a 13 0d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ACR_2147846422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ACR!MTB"
        threat_id = "2147846422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0d 2b 21 11 06 09 11 06 09 91 20 24 6d 6d ef 20 70 33 9b 7e 58 20 39 a0 08 6e 61 61 09 61 d2 9c 09 17 58 0d 09 11 06 8e 69 fe 04 2d d6}  //weight: 2, accuracy: High
        $x_1_2 = "MjCk1x.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CMO_2147846985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CMO!MTB"
        threat_id = "2147846985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 83 00 00 0a 7e 2e 00 00 04 08 07 6f 84 00 00 0a 28 44 00 00 0a 13 04 28 83 00 00 0a 11 04 16 11 04 8e 69 6f 84 00 00 0a 28 85 00 00 0a 13 05 7e 30 00 00 04}  //weight: 5, accuracy: High
        $x_5_2 = {09 07 6f 4a 00 00 0a 17 73 4b 00 00 0a 13 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RJ_2147847379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RJ!MTB"
        threat_id = "2147847379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 0e 11 06 17 58 13 06 11 06 11 05 8e 69 32 d1 06 16 8c ?? ?? ?? ?? 6f ?? ?? ?? 0a 26 06 6f ?? ?? ?? 0a 13 07 16 13 08 2b 34 11 07 11 08 9a 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RE_2147847380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RE!MTB"
        threat_id = "2147847380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "windwos\\bin\\Debug\\Dotfuscated\\windwos.pdb" ascii //weight: 1
        $x_1_2 = "$64d78a83-9274-4cd8-9dc8-e5f76f09ba37" ascii //weight: 1
        $x_1_3 = "https://www.linkpicture.com/q/converted_101.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXRK_2147848402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXRK!MTB"
        threat_id = "2147848402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AC4AMAAuADAALgAxAAAA" ascii //weight: 1
        $x_1_2 = "TgB0AGMAdQBkAG8AcgBQAAEAAQAiAAAA" ascii //weight: 1
        $x_1_3 = "Ic0JtAAOuh8OAAAAgAAAAAAAAAAA" ascii //weight: 1
        $x_1_4 = "Powered by SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AE_2147848439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AE!MTB"
        threat_id = "2147848439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 17 00 00 00 58 00 00 00 9e}  //weight: 2, accuracy: High
        $x_2_2 = "server.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AE_2147848439_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AE!MTB"
        threat_id = "2147848439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wcvzlm8pwdpsbuyx64335lhzt2mzfq27" ascii //weight: 1
        $x_1_2 = "6xvk9py559mzlydjwg876frq62sm3sfb" ascii //weight: 1
        $x_1_3 = "texkw4l3swqdzdyvpjyhcyyhsmt88naz" ascii //weight: 1
        $x_1_4 = "dt2fermwv3yyl5plv85w4xguzma6sm6v" ascii //weight: 1
        $x_1_5 = "8k5u586xkheshr2dtrdta2gcukvg2xss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASY_2147848530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASY!MTB"
        threat_id = "2147848530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 26 26 28 ?? ?? ?? 06 25 26 02 20 60 01 00 00 28 ?? ?? ?? 06 02 8e 69 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASY_2147848530_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASY!MTB"
        threat_id = "2147848530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 16 0c 2b 0f 02 7b 58 00 00 0a 08 07 08 91 9c 08 17 58 0c 08 19 32 ed de 0a 06 2c 06 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASY_2147848530_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASY!MTB"
        threat_id = "2147848530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 2b 1b 06 07 02 07 91 7e 02 00 00 04 07 7e 02 00 00 04 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASY_2147848530_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASY!MTB"
        threat_id = "2147848530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 02 8e 69 8d 15 00 00 01 0b 16 0c 16 0d 2b 17 07 09 02 09 91 06 08 91 61 d2 9c 08 17 58 06 8e 69 5d 0c 09 17 58 0d 09 02 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASY_2147848530_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASY!MTB"
        threat_id = "2147848530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 13 00 00 01 0a 06 72 41 00 00 70 6f ?? 00 00 0a 00 72 49 00 00 70 0b 06 6f ?? 00 00 0a 74 14 00 00 01 0c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASY_2147848530_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASY!MTB"
        threat_id = "2147848530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 2b 2d 06 08 6f ?? ?? ?? 0a 03 08 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 0d 07 09 28 ?? ?? ?? 0a 8c 3e 00 00 01 28 ?? ?? ?? 0a 0b 08 17 58 0c 08 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASY_2147848530_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASY!MTB"
        threat_id = "2147848530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 0d 16 13 04 2b 36 11 04 1f 30 5d 16 fe 01 13 05 11 05 2c 15 08 07 11 04 91 20 ff 00 00 00 61 b4 6f ?? 00 00 0a 00 00 2b 0d 00 08 07 11 04 91 6f ?? 00 00 0a 00 00 11 04 17 d6 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASY_2147848530_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASY!MTB"
        threat_id = "2147848530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 16 11 04 6f ?? ?? ?? 0a 00 00 09 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 25 13 04 16 fe 02 13 06 11 06 2d d5}  //weight: 2, accuracy: Low
        $x_1_2 = "RAT\\AsyncRat_0313\\rat_Client\\rat_pro\\obj\\Debug\\rat_pro.pdb" ascii //weight: 1
        $x_5_3 = "159.100.13.216" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXJK_2147849690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXJK!MTB"
        threat_id = "2147849690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 1f 49 58 20 ?? ?? ?? ?? 5d 13 06 11 07 09 11 06 91 58 20 ?? ?? ?? ?? 5d 13 07 09 11 06 91 13 05 09 11 06 09 11 07 91 9c 09 11 07 11 05 9c 09 11 06 91 09 11 07 91 58 20 ?? ?? ?? ?? 5d 13 09 02 11 08 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 09 11 09 91 61 d2 81 ?? ?? ?? ?? 11 08 17 58 13 08 11 08 02 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AY_2147849799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AY!MTB"
        threat_id = "2147849799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 0d 2b 30 08 09 a3 4b 00 00 01 13 04 28 ?? ?? ?? 06 11 04 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 2c 05 dd c9 00 00 00 de 03 26 de 00 09 17 58 0d 09 08 8e 69 32 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AY_2147849799_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AY!MTB"
        threat_id = "2147849799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VirtualMachineDetector" ascii //weight: 2
        $x_2_2 = "InstallationClass" ascii //weight: 2
        $x_2_3 = "EncryptionClass" ascii //weight: 2
        $x_2_4 = "FakeMessageClass" ascii //weight: 2
        $x_2_5 = "ZoneIdentifierClass" ascii //weight: 2
        $x_2_6 = "IWshRuntimeLibrary" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AADV_2147850033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AADV!MTB"
        threat_id = "2147850033"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 16 11 04 1f 0f 1e 28 ?? 00 00 0a 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38 ?? ff ff ff 02 28 ?? 00 00 0a 13 07 38 ?? 00 00 00 00 11 01 11 04 28 ?? 00 00 06 38 00 00 00 00 00 11 01 18 6f ?? 00 00 0a 38 ?? 00 00 00 11 09 13 00 38 ?? 00 00 00 28 ?? 00 00 06 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 13 09}  //weight: 3, accuracy: Low
        $x_1_2 = "dsfuhakbgj.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXFW_2147850805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXFW!MTB"
        threat_id = "2147850805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 e6}  //weight: 1, accuracy: High
        $x_1_2 = "9ubmFjIG1hcmdvcnAgc2loVCHNTAG4Ic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXF_2147851324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXF!MTB"
        threat_id = "2147851324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WoQAhbiygQleRoJRLtGBCZQYTLCk" ascii //weight: 1
        $x_1_2 = "wdGsVjTVw" ascii //weight: 1
        $x_1_3 = "nWcPvuKUdN" ascii //weight: 1
        $x_1_4 = "FRnnsbEVT" ascii //weight: 1
        $x_1_5 = "pOiYess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXG_2147851325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXG!MTB"
        threat_id = "2147851325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TPUXhQhHFJaUXphCRsLmwmMbkWGQ" ascii //weight: 1
        $x_1_2 = "xNBRYEepB" ascii //weight: 1
        $x_1_3 = "nHzSqEudaS" ascii //weight: 1
        $x_1_4 = "bbyFKaLtZ" ascii //weight: 1
        $x_1_5 = "MUNDess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CBY_2147851591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CBY!MTB"
        threat_id = "2147851591"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 0a 8d 3a 00 00 01 13 19 03 11 06 20 ?? ?? ?? ?? d6 11 18 1f 28 d8 d6 11 19 16 1f 28 28 ?? ?? ?? ?? 00 11 19 1a 94 17 da 17 d6 8d ?? ?? ?? ?? 13 1a 03 11 19 1b 94 11 1a 16}  //weight: 1, accuracy: Low
        $x_1_2 = {11 1a 8e 69 28 ?? ?? ?? ?? 00 12 0c 28 ?? ?? ?? ?? 11 19 19 94 d6 73 ?? ?? ?? ?? 13 0e 11 1a 8e 69 73 ?? ?? ?? ?? 13 0d 11 11 11 04 16 97 11 0e 11 1a 11 0d 28 ?? ?? ?? ?? b8 11 10 6f ?? ?? ?? ?? 26 11 18 17 d6 13 18 11 18 11 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CBYY_2147851675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CBYY!MTB"
        threat_id = "2147851675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CxfaywvGWc2wVDhE" wide //weight: 1
        $x_1_2 = "7zKUgty8pBVJGKPK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CBYZ_2147851676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CBYZ!MTB"
        threat_id = "2147851676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 0c 00 00 0a 0a 73 0d 00 00 0a 0b 07 28 ?? ?? ?? ?? 03 6f 0f 00 00 0a 6f 10 00 00 0a 0c 06 08 6f ?? ?? ?? ?? 06 18 6f 12 00 00 0a 06 6f 13 00 00 0a 02 16 02 8e 69 6f 14 00 00 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AAHP_2147851727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AAHP!MTB"
        threat_id = "2147851727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 01 00 06 03 08 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ADI_2147851881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ADI!MTB"
        threat_id = "2147851881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 06 09 28 ?? ?? ?? 06 25 26 20 67 03 00 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0a 08 1f 70 28 ?? ?? ?? 06 58 0c 08 07 8e 69 32 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXFF_2147852201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXFF!MTB"
        threat_id = "2147852201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 6c 07 6c 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5b ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 0d 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? 34 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 2b 24 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? 36 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 2b 0c 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 0d 06 08 07 1f 1e 09 69 09 69 09 69 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 08 17 58 0c 08 03 32 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXIO_2147888140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXIO!MTB"
        threat_id = "2147888140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 06 8e 69 33 02 16 0d 08 11 04 07 11 04 91 06 09 93 28 ?? ?? ?? ?? 61 d2 9c 09 17 58 0d 11 04 17 58 13 04 11 04 07 8e 69 32 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXIQ_2147888205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXIQ!MTB"
        threat_id = "2147888205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nchgnOaID" ascii //weight: 1
        $x_1_2 = "nNTaxbnFBo" ascii //weight: 1
        $x_1_3 = "MVrTSorQu" ascii //weight: 1
        $x_1_4 = "aQOmead" ascii //weight: 1
        $x_1_5 = "bufrNTaxbnFBo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CXJP_2147888295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CXJP!MTB"
        threat_id = "2147888295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 1c d2 13 37 11 1c 1e 63 d1 13 1c 11 1a 11 09 91 13 25 11 1a 11 09 11 25 11 2d 61 19 11 1f 58 61 11 37 61 d2 9c 11 25 13 1f 17 11 09 58 13 09 11 09 11 26 32 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AAMG_2147888645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AAMG!MTB"
        threat_id = "2147888645"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0d 07 09 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 04 11 04 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AOV_2147888897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AOV!MTB"
        threat_id = "2147888897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 16 15 28 ?? ?? ?? 0a 26 72 a3 00 00 70 16 16 15 28 ?? ?? ?? 0a 26 72 e7 00 00 70 16 16 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CCBW_2147892135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCBW!MTB"
        threat_id = "2147892135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JdQrUHqTYW" ascii //weight: 1
        $x_1_2 = "YJPgLEgslvag4RNL27X" ascii //weight: 1
        $x_1_3 = "Y4UcbTNTa4l0rgPFiYX" ascii //weight: 1
        $x_1_4 = "WrprkPFphX" ascii //weight: 1
        $x_1_5 = "b3QBkGrQmOsO34mVNKY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AAQZ_2147892181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AAQZ!MTB"
        threat_id = "2147892181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 11 05 09 28 ?? 00 00 06 1e 5b 28 ?? 00 00 06 28 ?? 00 00 06 09 17 28 ?? 00 00 06 08 09 28 ?? 00 00 06 17 28 ?? 00 00 06 13 06 11 06 02 16 02 8e 69 28 ?? 00 00 06 11 06}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AARA_2147892184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AARA!MTB"
        threat_id = "2147892184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 0d 2b 30 03 09 28 ?? 00 00 0a 04 09 04 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a da 0c 07 08 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 09 17 d6 0d 09 11 04 13 05 11 05 31 c7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AARI_2147892391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AARI!MTB"
        threat_id = "2147892391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 02 07 91 09 61 d2 9c 07 17 58 0b 07 02 8e 69 3f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AARQ_2147892474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AARQ!MTB"
        threat_id = "2147892474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 24 03 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "8ehgGSGo091GnP7s3UPExETz+yvMDAx1gTFeOp1NP6U=" wide //weight: 1
        $x_1_3 = "PrinterInfo.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AAY_2147892520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AAY!MTB"
        threat_id = "2147892520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 25 07 28 ?? 00 00 0a 0d 08 28 ?? 00 00 0a 06 07 28 ?? 00 00 0a 13 04 09 11 04 28 ?? 00 00 06 06 08 28 ?? 00 00 0a 13 05 11 05 28 ?? 00 00 06 11 04 73 ?? 00 00 0a 13 06 11 06 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CCCL_2147892763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCCL!MTB"
        threat_id = "2147892763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 06 08 91 20 ?? ?? ?? ?? 59 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CCCY_2147894250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCCY!MTB"
        threat_id = "2147894250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ent//////////////////////r///////////////yP//////////////////////oi///////////////////////////nt" wide //weight: 1
        $x_1_2 = "8zAEziopziopziopziop//8ziopziopLgAziopziopziop//8ziopziopLgziopziopz" wide //weight: 1
        $x_1_3 = "iopziA" wide //weight: 1
        $x_1_4 = "ziopziopgziopQziopziopziopgziopziopziopziopziopziopziopA" wide //weight: 1
        $x_1_5 = "TVqQAziopMzio" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AAVG_2147895185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AAVG!MTB"
        threat_id = "2147895185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 16 07 1f 0f 1f 10 28 ?? 01 00 06 7e ?? 01 00 04 06 07 28 ?? 01 00 06 7e ?? 01 00 04 06 18 28 ?? 01 00 06 7e ?? 01 00 04 06 1b 28 ?? 01 00 06 7e ?? 01 00 04 06 28 ?? 01 00 06 0d 7e ?? 01 00 04 09 02 16 02 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABNV_2147896330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABNV!MTB"
        threat_id = "2147896330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 08 07 28 ?? ?? ?? 0a 25 26 16 6f ?? ?? ?? 0a 25 26 13 05 12 05 28 ?? ?? ?? 0a 25 26 6f ?? ?? ?? 0a 00 07 09 12 01 28 ?? ?? ?? 0a 25 26 13 06 11 06 2d c8}  //weight: 4, accuracy: Low
        $x_1_2 = "Bitmap" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CCEF_2147897041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCEF!MTB"
        threat_id = "2147897041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e d5 35 00 04 06 7e d4 35 00 04 02 07 6f ?? 00 00 0a 7e 86 35 00 04 07 7e 86 35 00 04 8e 69 5d 91 61 28 ?? 33 00 06 28 ?? 33 00 06 26 07 17 58 0b 07 02 6f ?? 00 00 0a 32 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPX_2147897307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPX!MTB"
        threat_id = "2147897307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 8e 69 5d 18 58 1b 58 1d 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPX_2147897307_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPX!MTB"
        threat_id = "2147897307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 07 00 59 3b 40 01 00 00 fe 0c 02 00 1f fe fe 0e 08 00 fe 0c 08 00 65 3b e7 00 00 00 fe 0c 02 00 1f fc fe 0e 09 00 16 fe 0e 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPX_2147897307_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPX!MTB"
        threat_id = "2147897307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AsyncClient" ascii //weight: 1
        $x_1_2 = "Pastebin" ascii //weight: 1
        $x_1_3 = "KeepAlivePacket" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "Antivirus" ascii //weight: 1
        $x_1_6 = "CreateMutex" ascii //weight: 1
        $x_1_7 = "GetForegroundWindow" ascii //weight: 1
        $x_1_8 = "StrReverse" ascii //weight: 1
        $x_1_9 = "get_OSFullName" ascii //weight: 1
        $x_1_10 = "set_UseShellExecute" ascii //weight: 1
        $x_1_11 = "ActivatePong" ascii //weight: 1
        $x_1_12 = "AsyncResult" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AMBB_2147897541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AMBB!MTB"
        threat_id = "2147897541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 07 07 06 25 13 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 1f 10 02 8e 69 1f 10 59 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {06 0a 06 02 7d ?? 00 00 04 06 7b ?? 00 00 04 17 6f ?? 00 00 0a 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AAYQ_2147898447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AAYQ!MTB"
        threat_id = "2147898447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 1f 10 8d ?? 00 00 01 0c 07 08 16 08 8e 69 6f ?? 00 00 0a 26 06 08 6f ?? 00 00 0a 07 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 de 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "GetTempPath" ascii //weight: 1
        $x_1_3 = "WriteAllBytes" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AAAO_2147899845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AAAO!MTB"
        threat_id = "2147899845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 18 58 1e 58 1f 0a 59 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1e 58 1f 0a 59 91 61 28 ?? ?? 00 06 03 08 20 87 10 00 00 58 20 86 10 00 00 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_BA_2147900110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.BA!MTB"
        threat_id = "2147900110"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 16 0c 2b 20 08 02 07 02 8e 69 5d 91 58 06 07 91 58 20 ff 00 00 00 5f 0c 06 07 08 28 09 00 00 06 07 17 58 0b 07 20 00 01 00 00 32 d8 06 2a}  //weight: 1, accuracy: High
        $x_1_2 = "Crypted.exe" wide //weight: 1
        $x_2_3 = {72 01 00 00 70 6f 0b 00 00 0a 06 72 17 00 00 70 6f 0c 00 00 0a 06 17 6f 0d 00 00 0a 06 17 6f 0e 00 00 0a 06 28 0f 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRat_CCGI_2147900374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCGI!MTB"
        threat_id = "2147900374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Payload executed successfully in process {0} with new image base: 0x{1:X}" wide //weight: 1
        $x_1_2 = "StartBase:" wide //weight: 1
        $x_1_3 = ":EndBase" wide //weight: 1
        $x_1_4 = "Roaming\\dropped.exe" wide //weight: 1
        $x_1_5 = "system32\\notepad.exe" wide //weight: 1
        $x_1_6 = "payload" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ANAA_2147900497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ANAA!MTB"
        threat_id = "2147900497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 11 04 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 18 6f ?? 00 00 0a 00 25 07 6f ?? 00 00 0a 00 13 08 11 08 6f ?? 00 00 0a 13 09 11 09 09 16 09 8e 69 6f ?? 00 00 0a 13 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AZAA_2147900817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AZAA!MTB"
        threat_id = "2147900817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 1c 13 0b 2b a8 09 74 ?? 00 00 01 09 75 ?? 00 00 01 6f ?? 00 00 0a 09 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 19 13 0b 2b 80}  //weight: 2, accuracy: Low
        $x_2_2 = {02 16 02 8e 69 6f ?? 00 00 0a 11 07 75 ?? 00 00 01 6f ?? 00 00 0a 16 13 0f 2b bf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MH_2147901652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MH!MTB"
        threat_id = "2147901652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xwczpnavqpl" wide //weight: 1
        $x_1_2 = "b56053a2-de82-4d07-a8b2-19932fe1a8a5" ascii //weight: 1
        $x_1_3 = "http://localhost/json/ws.php" wide //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "GetRequestStream" ascii //weight: 1
        $x_1_6 = "AwakeReg" wide //weight: 1
        $x_1_7 = "powershell" wide //weight: 1
        $x_1_8 = "Start-Sleep -s 10" wide //weight: 1
        $x_1_9 = "Reverse" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_SG_2147902186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.SG!MTB"
        threat_id = "2147902186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UriHostNameType" ascii //weight: 1
        $x_1_2 = "RatClientTest" ascii //weight: 1
        $x_1_3 = "\\RatClientTest.pdb" ascii //weight: 1
        $x_1_4 = "Hi ponita" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_AsyncRat_SGC_2147902265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.SGC!MTB"
        threat_id = "2147902265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0d 00 00 06 11 00 6f 03 00 00 0a 28 0e 00 00 06 28 01 00 00 2b 6f 05 00 00 0a 28 02 00 00 2b}  //weight: 1, accuracy: High
        $x_1_2 = "Ymcfcbdts.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_SGB_2147902275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.SGB!MTB"
        threat_id = "2147902275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunBotKiller" ascii //weight: 1
        $x_1_2 = "ShellWriteLine" ascii //weight: 1
        $x_1_3 = "SetHook" ascii //weight: 1
        $x_1_4 = "injection" ascii //weight: 1
        $x_2_5 = "Stub.g.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AsyncRat_SGD_2147902374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.SGD!MTB"
        threat_id = "2147902374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 28 0c 00 00 0a 7e 02 00 00 04 6f 12 00 00 0a 28 19 00 00 06 72 01 00 00 70 28 13 00 00 0a 7e 03 00 00 04 28 0d 00 00 0a 6f 14 00 00 0a 0b de 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPZ_2147903143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPZ!MTB"
        threat_id = "2147903143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 9e 06 19 06 19 95 07 19 95 61 ?? ?? ?? ?? ?? 61 9e 06 1a 06 1a 95 07 1a 95 58 ?? ?? ?? ?? ?? 5a 9e 06 1b 06 1b 95 07 1b 95 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_SGE_2147904339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.SGE!MTB"
        threat_id = "2147904339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 0b 00 00 04 6f 1d 00 00 0a 6f 1e 00 00 0a 74 2e 00 00 01 28 19 00 00 0a 7e 07 00 00 04 6f 1f 00 00 0a 28 49 00 00 06 72 01 00 00 70 28 20 00 00 0a 7e 0a 00 00 04 28 1a 00 00 0a 6f 21 00 00 0a 0a dd 08 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_SGF_2147904863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.SGF!MTB"
        threat_id = "2147904863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunHiddenCommand" ascii //weight: 1
        $x_1_2 = "powershell.exe" wide //weight: 1
        $x_1_3 = "RawAccel.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_SGG_2147908722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.SGG!MTB"
        threat_id = "2147908722"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 0d 00 00 04 7e 09 00 00 04 6f 4f 00 00 06 28 07 00 00 0a 73 09 00 00 0a 80 0b 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AMMH_2147908983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AMMH!MTB"
        threat_id = "2147908983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 03 07 6f ?? 00 00 0a 61 d1 0d 12 03 28 ?? 00 00 0a 13 04 06 11 04 6f ?? 00 00 0a 26 07 03 6f ?? 00 00 0a 17 59 3b ?? 00 00 00 07 17 58 38 ?? 00 00 00 16 0b 08 18 58 0c 08 02 6f ?? 00 00 0a 32 b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AMMH_2147908983_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AMMH!MTB"
        threat_id = "2147908983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0c 02 00 fe 0c 01 00 6f ?? 00 00 0a 20 01 00 00 00 73 ?? 00 00 0a 25 fe 0c 00 00 20 ?? 00 00 00 fe 0c 00 00 8e 69 6f ?? 00 00 0a 25 6f ?? 00 00 0a fe 0c 02 00 6f ?? 00 00 0a fe 0e 00 00 fe 0c 02 00 6f ?? 00 00 0a 6f ?? 00 00 0a 20 ?? ff ff ff 28 ?? 00 00 0a fe 0e 03 00}  //weight: 2, accuracy: Low
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_4 = "get_IsAttached" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPY_2147913605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPY!MTB"
        threat_id = "2147913605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 1f 16 5d 91 13 04 07 09 91 11 04 61 13 05 09 17 58 08 5d 13 06 07 11 06 91 13 07 20 00 01 00 00 13 08 11 05 11 07 59 11 08 58 11 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_RPY_2147913605_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.RPY!MTB"
        threat_id = "2147913605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 28 1a 01 00 06 00 02 07 6c 02 28 0d 01 00 06 6c 5b 23 00 00 00 00 00 00 59 40 5a 28 10 01 00 06 00 07 17 d6 0b 07 06 31 d5 02 17 73 2e 01 00 06 6f 28 01 00 06 00 2a 00 00 00 13 30 01 00 07 00 00 00 07 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CCJB_2147915532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCJB!MTB"
        threat_id = "2147915532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C6kwJmyHsdyS9irNuA.g07SvQprQaSYOmPnVC" wide //weight: 1
        $x_1_2 = "3AQlV9HZKxbYaLJ8AN.JQO2QUSpxwForDRja3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_BL_2147918097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.BL!MTB"
        threat_id = "2147918097"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 8e 69 6f ?? 00 00 0a 08 6f}  //weight: 2, accuracy: Low
        $x_4_3 = {0a 0b 16 2d e2 73 ?? 00 00 0a 0c 08 07 17 73}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_KAV_2147920664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.KAV!MTB"
        threat_id = "2147920664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 11 05 93 13 06 11 06 09 d6 6a 13 07 07 11 07 20 80 00 00 00 6a da b7 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 11 05 17 d6 13 05 11 05 11 04 8e 69 fe 04 13 08 11 08 2d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CCJC_2147922093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCJC!MTB"
        threat_id = "2147922093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 09 11 0b 58 91 08 11 0b 91 2e 05 16 13 0a 2b 0c 11 0b 17 58 13 0b 11 0b 11 05 32 e2}  //weight: 1, accuracy: High
        $x_2_2 = {11 08 11 0c 07 11 06 11 0c 58 91 9c 11 0c 17 58 13 0c 11 0c 11 07 32 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CCJN_2147925086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCJN!MTB"
        threat_id = "2147925086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 72 f4 6e 00 70 13 04 09 11 04 ?? fa 6e 00 70 28 ?? 00 00 0a 20 00 01 00 00 14 14 17 8d 13 00 00 01 25 16 08 a2 ?? 6b 00 00 0a 75 21 00 00 01 13 05 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CCJN_2147925086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CCJN!MTB"
        threat_id = "2147925086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 09 91 6f ?? ?? ?? ?? 09 04 17 58 58 0d 09 02 8e 69 32 eb 06 6f ?? ?? ?? ?? 0b 07 8e 69 8d ?? ?? ?? ?? 0c 16 13 04 2b 18 08 11 04 07 11 04 91 03 11 04 03 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASN_2147926343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASN!MTB"
        threat_id = "2147926343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0b 16 0c 2b 19 00 06 08 8f 0f 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 00 08 17 58 0c 08 06 8e 69 fe 04 0d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AMCY_2147929652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AMCY!MTB"
        threat_id = "2147929652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 08 16 08 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 de 22}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AYS_2147933088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AYS!MTB"
        threat_id = "2147933088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 2b 12 00 7e ?? 00 00 04 11 05 16 11 04 6f ?? ?? ?? 0a 00 00 09 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 25 13 04 16 fe 02 13 06 11 06 2d d5}  //weight: 2, accuracy: Low
        $x_5_2 = "159.100.13.216" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AYS_2147933088_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AYS!MTB"
        threat_id = "2147933088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a2 06 1c 8d ?? 00 00 01 25 16 28 ?? 00 00 06 a2 25 17 28 ?? 00 00 06 a2 25 18 28 ?? 00 00 06 a2 25 19 28 ?? 00 00 06 a2 25 1a 28 ?? 00 00 06 a2 25 1b 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Rental.View.ASC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AXKA_2147933090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AXKA!MTB"
        threat_id = "2147933090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 19 58 19 59 91 61 03 08 20 10 02 00 00 58 20 0f 02 00 00 59 18 59 18 58 03 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ARS_2147933342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ARS!MTB"
        threat_id = "2147933342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 08 06 07 6f ?? 00 00 0a 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 00 de 0b 08 2c 07 08 6f ?? 00 00 0a 00 dc 72 ?? 00 00 70 28 ?? 00 00 0a 00 07 28}  //weight: 1, accuracy: Low
        $x_2_2 = "207.231.111.48" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ART_2147935414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ART!MTB"
        threat_id = "2147935414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 09 28 ?? 00 00 0a 11 04 28 ?? 00 00 0a 26 28 ?? 00 00 0a 06 28 ?? 00 00 0a 13 05 11 05 08 28 ?? 00 00 0a 11 05 28}  //weight: 1, accuracy: Low
        $x_2_2 = "dwdtte4wjfk8ds5.hopto.org" wide //weight: 2
        $x_3_3 = "pristolmag32dds.hopto.org" wide //weight: 3
        $x_4_4 = "anticoresa9923p.hopto.org" wide //weight: 4
        $x_5_5 = "mppr.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ASA_2147935767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ASA!MTB"
        threat_id = "2147935767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 13 02 11 12 11 13 16 11 13 8e 69 28 ?? 00 00 0a 7e 07 00 00 04 12 03 7b 0b 00 00 04 11 0c 11 10 58 11 13 11 13 8e 69 12 01 6f ?? 00 00 06 2d 06 73 0b 00 00 0a 7a 11 0d 1f 28 58 13 0d 11 0f 17 58 13 0f 11 0f 11 0e 32 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AVNA_2147935850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AVNA!MTB"
        threat_id = "2147935850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 10 02 00 00 58 20 0f 02 00 00 59 1a 59 1a 58 03 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fb 00 00 00 58 1a 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ATR_2147936726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ATR!MTB"
        threat_id = "2147936726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e b7 17 da 13 07 13 06 2b 21 09 11 06 91 11 04 11 06 11 04 8e b7 5d 91 61 13 05 08 11 05 6f ?? ?? ?? 0a 00 00 11 06 17 d6 13 06 11 06 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ATR_2147936726_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ATR!MTB"
        threat_id = "2147936726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 07 11 08 e0 58 09 11 08 91 52 11 07 11 08 e0 58 47 09 11 08 91 33 e8 11 08 17 58 13 08 11 08 1e}  //weight: 2, accuracy: High
        $x_1_2 = {0d 16 13 06 2b 15 09 11 06 8f ?? 00 00 01 25 47 1f 0a 59 d2 52 11 06 17 58 13 06 11 06 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AWOA_2147936788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AWOA!MTB"
        threat_id = "2147936788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 0f 02 00 00 58 20 0e 02 00 00 59 19 59 19 58 03 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1a 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AYPA_2147937747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AYPA!MTB"
        threat_id = "2147937747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 1c 58 1c 59 91 61 06 09 20 11 02 00 00 58 20 10 02 00 00 59 06 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 1c 58 1c 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 09 17 58 0d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ADQA_2147937984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ADQA!MTB"
        threat_id = "2147937984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0b 20 aa 00 00 00 0c 16 13 04 2b 14 07 11 04 8f 15 00 00 01 25 47 08 61 d2 52 11 04 17 58 13 04 11 04 07 8e 69 32 e5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AHQA_2147938136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AHQA!MTB"
        threat_id = "2147938136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0e 04 00 fe 0c 04 00 20 01 00 00 00 40 00 00 00 00 02 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0b 06 8e 69 8d 1f 00 00 01 0c 16 0d 38 13 00 00 00 08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 3f e4 ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ALQA_2147938289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ALQA!MTB"
        threat_id = "2147938289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 11 06 09 11 06 91 11 04 11 06 11 04 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 3f db ff ff ff}  //weight: 3, accuracy: High
        $x_2_2 = {fe 0e 07 00 fe 0c 07 00 20 01 00 00 00 40 00 00 00 00 02 28 ?? 00 00 06 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 6f ?? 00 00 0a 0a 1a 06 6f ?? 00 00 0a 1a 5d 59 0b 07 1a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_MVT_2147938513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.MVT!MTB"
        threat_id = "2147938513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 1e 5d 16 fe 01 13 06 11 06 2c 0f 02 11 05 02 11 05 91 20 a9 00 00 00 61 b4 9c 11 05 17 d6 13 05 11 05 11 04 31 d8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CE_2147939350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CE!MTB"
        threat_id = "2147939350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 05 07 58 09 8e 69 5d 91 11 05 1f 0d 5a 20 ?? ?? ?? ?? 5d 61 07 11 05 19 5d 1f 1f 5f 63 61 d2 13 09 11 04 11 05 11 08 11 09 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CF_2147939798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CF!MTB"
        threat_id = "2147939798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 04 07 8e 69 5d 91 08 61 11 04 1f 1f 5a 61 d2 13 06 09 11 04 11 05 11 06 61 d2 9c 11 04 17 58 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_CG_2147940181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.CG!MTB"
        threat_id = "2147940181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 12 14 28 ?? ?? ?? ?? 9c 25 17 12 14 28 ?? ?? ?? ?? 9c 25 18 12 14 28 ?? ?? ?? ?? 9c 13 10 16 13 05 2b 11 07 11 10 11 05 91 6f ?? ?? ?? ?? 11 05 17 58 13 05 11 05 11 06 fe 04 13 11 11 11 2d e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ZZT_2147944030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ZZT!MTB"
        threat_id = "2147944030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 08 8e 69 8d ?? 00 00 01 13 04 16 13 05 2b 12 11 04 11 05 08 11 05 91 09 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 0e 11 0e 2d e1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ACY_2147944530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ACY!MTB"
        threat_id = "2147944530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 17 da 17 d6 8d ?? ?? ?? 01 0b 02 8e 69 17 da 0c 16 0d 2b 19 07 09 02 09 91 19 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 09 17 d6 0d 09 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_BSA_2147945876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.BSA!MTB"
        threat_id = "2147945876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Skipping Annabelle.exe" ascii //weight: 10
        $x_1_2 = "powershell.exe" ascii //weight: 1
        $x_1_3 = "ExecutionPolicy Bypass -File" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_PPQ_2147949926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.PPQ!MTB"
        threat_id = "2147949926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 00 04 28 ?? 05 00 06 80 ?? 00 00 04 7e ?? 00 00 04 73 ?? 00 00 06 80 ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 7e}  //weight: 10, accuracy: Low
        $x_1_2 = {50 61 73 74 65 5f 62 69 6e 00 42 53 5f 4f 44 00 48 77 5f 69 64 00 44 65 5f 6c 61 79 00 47 72 6f 75 70 00 41 6e 74 69 5f 50 72 6f 63 65 73 73 00 41 6e 5f 74 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AVIB_2147955919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AVIB!MTB"
        threat_id = "2147955919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 06 14 13 07 1f 18 13 08 11 08 1f 18 fe 04 13 13 11 13 2c 04 1f 18 13 08 11 08 1f 17 d6 1f 18 5b 1f 18 d8 13 08 11 08 17 da 17 d6 8d ?? 00 00 01 13 09 16 13 0a 2b 0d 11 09 11 0a 14 a2 11 0a 17 d6 13 0a 00 11 0a 11 08 17 da fe 04 13 14 11 14 2d e5}  //weight: 4, accuracy: Low
        $x_2_2 = {72 8d 75 01 70 13 0b 72 95 75 01 70 13 0c 72 9d 75 01 70 13 0d 72 a5 75 01 70 13 0e 11 0b 11 0c 11 0d 11 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ZOL_2147956465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ZOL!MTB"
        threat_id = "2147956465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 1f 64 fe 0e 06 00 20 60 00 00 00 20 26 aa 62 2b 20 0f fd 48 2b 61 20 29 57 2a 00 40 10 00 00 00 20 02 00 00 00 fe 0e 06 00 fe ?? 18 00 00 01 58 00 fe 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ANKB_2147957247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ANKB!MTB"
        threat_id = "2147957247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {58 4a 07 8e 69 5d 1d 58 1f 0e 58 1f 16 59 1f 18 58 1f 17 59 91 61 02 06 1a 58 4a 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 02 8e 69 5d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_AJLB_2147957804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.AJLB!MTB"
        threat_id = "2147957804"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 20 ?? ?? 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 20 ?? ?? 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 de 23}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_ABA_2147958891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.ABA!MTB"
        threat_id = "2147958891"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 17 8d 7e 00 00 01 25 16 12 05 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 20 ?? ca e4 b6 38 ?? fe ff ff 11 19 20 ?? e1 57 47 5a 20 ?? f4 ba 70 61 38 ?? fe ff ff 08 6f ?? 00 00 0a 1f 1f 5a 13 17 11 19 20 ?? af a8 02 5a 20 ?? 10 d4 8f 61}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AsyncRat_PW_2147959411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AsyncRat.PW!MTB"
        threat_id = "2147959411"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {03 04 20 8a a5 08 00 58 05 58 61 10 01 03 2a}  //weight: 3, accuracy: High
        $x_2_2 = "twerjhituhq.erywerkigs" ascii //weight: 2
        $x_1_3 = "0de7a420-82ad-4e15-806b-9a3f29a5bbad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


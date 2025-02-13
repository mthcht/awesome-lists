rule VirTool_MSIL_CryptInject_AC_2147730194_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.AC!MTB"
        threat_id = "2147730194"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0c 11 15 11 0b 9e 11 0d 11 15 11 09 9e 11 09 1b 64 11 09 1f 1b 62 60 13 08 11 0a 19 64 11 0a 1f 1d 62 60 13 09 11 0b 1d 64 11 0b 1f 19 62 60 13 0a 11 08 1f 0b 64 11 08 1f 15 62 60 13 0b 11 15 17 58 13 15}  //weight: 1, accuracy: High
        $x_1_2 = {12 00 28 38 00 00 06 06 6f 22 00 00 0a 16 31 10 06 16 6f 23 00 00 0a 20 ae 00 00 00 fe 01 2b 01 16 0b 28 24 00 00 0a 28 25 00 00 0a 0c 08 08 1f 3c 58 4b e0 58 25 1c 58 49 0d 25 1f 14 58 49 13 04 16 e0 13 05 16 13 06 1f 18 58 11 04 58 13 07}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_CD_2147730350_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.CD!MTB"
        threat_id = "2147730350"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 11 05 9a 0c 08 6f ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 2c 21}  //weight: 1, accuracy: Low
        $x_1_2 = {08 14 17 8d 01 00 00 01 13 06 11 06 16 02 a2 11 06 6f ?? 00 00 0a 74 ?? 00 00 01 0d de 13 26 de 00}  //weight: 1, accuracy: Low
        $x_1_3 = {91 61 d2 9c}  //weight: 1, accuracy: High
        $x_1_4 = "GetExecutingAssembly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_CF_2147730711_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.CF!MTB"
        threat_id = "2147730711"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 0f 00 00 0a 26 16 0a 2b 0c 28 03 00 00 06 2c 01 2a 06 17 58 0a 06 1b 32 f0 2a}  //weight: 1, accuracy: High
        $x_1_2 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_CG_2147731222_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.CG!MTB"
        threat_id = "2147731222"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "||I|E||" wide //weight: 1
        $x_1_2 = "CreateInstance" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YA_2147731286_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YA!MTB"
        threat_id = "2147731286"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 03 00 00 0a 6f 04 00 00 0a 16 9a 6f 05 00 00 0a 28 06 00 00 0a 0a 06 28 07 00 00 0a 0b 07 73 08 00 00 0a 0c 08 28 02 00 00 06 26 28 03 00 00 0a 6f 04 00 00 0a 16 9a 6f 05 00 00 0a 1a 17 73 09 00 00 0a 0d 09 6f 0a 00 00 0a 69 13 04 11 04 20 00 ?? ?? 00 59 13 05 09 11 05 20 00 ?? ?? 00 28 04 00 00 06 13 06 09 6f 0b 00 00 0a 73 0c 00 00 0a 13 07 11 07 20 d0 07 00 00 6f 0d 00 00 0a 13 08 72 01 00 00 70 11 08 8c 0e 00 00 01 72 05 00 00 70 28 0e 00 00 0a 1a 18 73 09 00 00 0a 13 09 11 09 11 06 28 06 00 00 06 11 09 6f 0b 00 00 0a 72 01 00 00 70 11 08 8c 0e 00 00 01 72 05 00 00 70 28 0e 00 00 0a 28 0f 00 00 0a 13 0a 11 0a 6f 10 00 00 0a de 03 26 de 00}  //weight: 1, accuracy: Low
        $x_1_2 = {de 1c 72 01 00 00 70 11 08 8c 0e 00 00 01 72 05 00 00 70 28 0e 00 00 0a 28 11 00 00 0a dc 73 0c 00 00 0a 13 0b 11 0b 17 1a 6f 12 00 00 0a 19 33 12 16 72 11 00 00 70 72 65 00 00 70 16 28 11 00 00 06 26 2a}  //weight: 1, accuracy: High
        $x_1_3 = {06 09 6f 33 00 00 0a 0c 08 03 61 d1 0c 07 08 6f 34 00 00 0a 26 09 17 58 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YB_2147731301_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YB!MTB"
        threat_id = "2147731301"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters" wide //weight: 1
        $x_1_2 = "SbieDll.dll" wide //weight: 1
        $x_1_3 = "InstallUtil.exe" wide //weight: 1
        $x_1_4 = "svchost.exe" wide //weight: 1
        $x_1_5 = "AppLaunch.exe" wide //weight: 1
        $x_1_6 = "vbc.exe" wide //weight: 1
        $x_1_7 = "RegAsm.exe" wide //weight: 1
        $x_1_8 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YB_2147731301_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YB!MTB"
        threat_id = "2147731301"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0c 16 11 0c 16 95 11 0d 16 95 61 9e 11 0c 17 11 0c 17 95 11 0d 17 95 5a 9e 11 0c 18 11 0c 18 95 11 0d 18 95 58 9e 11 0c 19 11 0c 19 95 11 0d 19 95 61 9e 11 0c 1a 11 0c 1a 95 11 0d 1a 95 5a 9e 11 0c 1b 11 0c 1b 95 11 0d 1b 95 58 9e 11 0c 1c 11 0c 1c 95 11 0d 1c 95 61 9e 11 0c 1d 11 0c 1d 95 11 0d 1d 95 5a 9e 11 0c 1e 11 0c 1e 95 11 0d 1e 95 58 9e 11 0c 1f 09 11 0c 1f 09 95 11 0d 1f 09 95 61 9e 11 0c 1f 0a 11 0c 1f 0a 95 11 0d 1f 0a 95 5a 9e 11 0c 1f 0b 11 0c 1f 0b 95 11 0d 1f 0b 95 58 9e 11 0c 1f 0c 11 0c 1f 0c 95 11 0d 1f 0c 95 61 9e 11 0c 1f 0d 11 0c 1f 0d 95 11 0d 1f 0d 95 5a 9e 11 0c 1f 0e 11 0c 1f 0e 95 11 0d 1f 0e 95 58 9e 11 0c 1f 0f 11 0c 1f 0f 95 11 0d 1f 0f 95 61 9e 1f 40 13 0e}  //weight: 1, accuracy: High
        $x_1_2 = {11 0c 11 14 11 0b 9e 11 0d 11 14 11 09 9e 11 09 1b 64 11 09 1f 1b 62 60 13 08 11 0a 19 64 11 0a 1f 1d 62 60 13 09 11 0b 1d 64 11 0b 1f 19 62 60 13 0a 11 08 1f 0b 64 11 08 1f 15 62 60 13 0b 11 14 17 58 13 14}  //weight: 1, accuracy: High
        $x_1_3 = {03 25 4b 04 06 1f 0f 5f 95 61 54 04 06 1f 0f 5f 04 06 1f 0f 5f 95 03 25 1a 58 10 01 4b 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YD_2147731701_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YD!MTB"
        threat_id = "2147731701"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 1f 1f 5f 1f 18 62 7e 69 00 00 04 08 25 17 58 0c 91 1f 10 62 58 7e 69 00 00 04 08 25 17 58 0c 91 1e 62 58 7e 69 00 00 04 08 25 17 58 0c 91 58 0b}  //weight: 1, accuracy: High
        $x_1_2 = {16 0b 02 0c 7e 69 00 00 04 08 25 17 58 0c 91 0d 09 20 80 00 00 00 5f 3a 14 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_2147731820_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject!MTB"
        threat_id = "2147731820"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".fuck.exe" ascii //weight: 1
        $x_1_2 = "Inject" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_2147731820_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject!MTB"
        threat_id = "2147731820"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d0 0e 00 00 01 28 ?? 00 00 0a 72 ?? ?? ?? 70 17 fe 0e 03 00 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 10 00 00 00 20 02 00 00 00 fe 0e 03 00 fe ?? ?? 00 00 01 58 00 8d 01 00 00 01 0b 07 16 fe 0e 04 00 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 ?? 00 00 00 20 ?? 00 00 00 fe 0e 04 00 fe ?? ?? 00 00 01 58}  //weight: 1, accuracy: Low
        $x_1_2 = {d0 0e 00 00 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 17 8d 01 00 00 01 0b 07 16 28 ?? 00 00 06 28 ?? 00 00 0a a2 07 28 ?? 00 00 06 75 ?? 00 00 01 0a d0 ?? 00 00 02 28 ?? 00 00 0a 72 ?? ?? ?? 70 17 8d 01 00 00 01 0c 08 16 06 a2 08 28 0e 00 00 06 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_CryptInject_YF_2147731891_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YF!MTB"
        threat_id = "2147731891"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 eb 45 d0 04 20 e8 6f 40 fd 20 ac a9 ec a6 59 66 20 e9 32 2e b1 20 db b0 97 f6 20 04 14 a1 c2 5a 61 61 61 07 66 20 16 fd 6a c9 20 96 68 94 4e 65 20 f5 f0 3e 62 65 61 20 10 b6 69 58 65 20 55 37 28 c0 66 61 59 20 d1 65 5c 40 65 65 20 5b f5 89 cc 20 0d 4a 58 98 61 20 57 43 3a f5 20 2f a7 89 74 61 58 59 58 61 61 59 20 01 42 a8 c4 5a 20 6c 67 6d 02 66 58 20 b8 79 27 fa 66 61 65 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YG_2147731944_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YG!MTB"
        threat_id = "2147731944"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 f4 01 00 00 28 1e 00 00 0a 07 20 82 44 f9 b1 5a 20 19 a1 90 fe 61 2b aa 06 28 1f 00 00 0a 6f 1a 00 00 0a 07 20 50 5e 3c 75 5a 20 0c 7f 4f c2 61 2b 90 06 6f 20 00 00 0a 2c 08 20 e7 55 2f 31 25 2b 06 20 c2 86 f3 79 25 26 38 74 ff ff ff 28 21 00 00 0a 2c 08 20 90 7d e5 ad 25 2b 06 20 58 64 f0 cb 25 26 07 20 a6 d3 54 d3 5a 61 38 51 ff ff ff 28 22 00 00 0a 2c 08 20 7c 66 33 2f 25 2b 06 20 71 f1 b2 51 25 26 38 36 ff ff ff 14 28 14 00 00 0a 07 20 a8 58 51 df 5a 20 4f 0b 28 cf 61 38 1e ff ff ff 14 28 14 00 00 0a 20 b4 7f 26 49 38 0e ff ff ff 14 fe 06 03 00 00 06 73 17 00 00 0a 73 18 00 00 0a 0a 06 17 6f 19 00 00 0a 07 20 c6 4a 07 b6 5a 20 ed 62 22 d4 61 38 e3 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {14 28 14 00 00 0a 08 20 49 31 12 16 5a 20 fe 45 08 39 61 2b bb 07 2d 08 20 31 e1 b3 a4 25 2b 06 20 09 74 0e 85 25 26 08 20 81 5a e0 0e 5a 61 2b 9f d0 1e 00 00 01 28 15 00 00 0a 72 09 00 00 70 17 8d 06 00 00 01 25 16 d0 20 00 00 01 28 15 00 00 0a a2 6f 16 00 00 0a 0b 08 20 57 2f 6b 75 5a 20 fb fa 77 41 61 38 65 ff ff ff 14 fe 06 03 00 00 06 73 17 00 00 0a 73 18 00 00 0a 25 17 6f 19 00 00 0a 14 6f 1a 00 00 0a 20 ee da 46 c6 38 3d ff ff ff 72 37 00 00 70 07 14 17 8d 04 00 00 01 25 16 06 72 3b 00 00 70 28 1b 00 00 0a a2 6f 1c 00 00 0a 6f 1d 00 00 0a 2d 08 20 1e 59 68 c3 25 2b 06 20 d7 90 72 eb 25 26 08 20 64 d9 1c d7 5a 61 38 fa fe ff ff 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YJ_2147733890_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YJ!MTB"
        threat_id = "2147733890"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clsOldRunPe" wide //weight: 1
        $x_1_2 = "RegPersistance" ascii //weight: 1
        $x_1_3 = "RunPersistence" ascii //weight: 1
        $x_1_4 = ".VmDetector.Win32" ascii //weight: 1
        $x_1_5 = "FilePersistance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YK_2147734502_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YK!MTB"
        threat_id = "2147734502"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 04 00 00 0a 28 05 00 00 0a 6f 06 00 00 0a 14 14 6f 07 00 00 0a 26 ?? 28 08 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YL_2147735350_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YL!MTB"
        threat_id = "2147735350"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 17 00 00 0a 9c 06 07 17 58 11 04 11 05 28 17 00 00 0a 68 1e 63 9c 06 07 06 07 91 1f 32 61 9c 06 07 06 07 91 07 59 1f 1e 59 9c 06 07 06 07 91 1f 0a 61 9c 06 07 17 58 06 07 17 58 91 1f 32 61 9c 06 07 17 58 06 07 17 58 91 07 59 1f 1f 59 9c 06 07 17 58 06 07 17 58 91 1f 0a 61 9c 11 05 17 58 13 05 07 18 58 0b 11 05 11 04 28 32 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YO_2147740115_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YO!MTB"
        threat_id = "2147740115"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 91 1f ?? 61 [0-2] 02 8e ?? 17 d6 [0-7] 02 8e ?? 17 da [0-10] 11 ?? 02 11 ?? 91 [0-2] 61 07 [0-2] 91 61 b4 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YQ_2147740596_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YQ!MTB"
        threat_id = "2147740596"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\RegAsm.exe" wide //weight: 5
        $x_5_2 = "\\temp\\notepad.exe" wide //weight: 5
        $x_5_3 = "\\Start Menu\\Programs\\Startup\\file.exe" wide //weight: 5
        $x_1_4 = "REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f" wide //weight: 1
        $x_1_5 = "REG add HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System /v DisableCMD /t REG_DWORD /d 1 /f" wide //weight: 1
        $x_1_6 = "REG add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoFolderOptions /t REG_DWORD /d 1 /f" wide //weight: 1
        $x_1_7 = "REG add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoFolderOptions /t REG_DWORD /d 1 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_CryptInject_YR_2147740924_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YR!MTB"
        threat_id = "2147740924"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 09 00 00 28 ?? 00 00 0a fe 0e 00 00 28 ?? 00 00 0a fe 0c 00 00 6f ?? 00 00 0a fe 0e 01 00 38 00 00 00 00 fe 0c 01 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "RHVwbGljYXRlZCBhc3NlbWJseSBpZCAnezA6Tn0nLCBpZ25vcmluZy4=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YS_2147741014_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YS!MTB"
        threat_id = "2147741014"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 07 11 07 13 08 11 08 1f ?? d6 13 09 11 08 1f 5a 30 0b 11 08 1f 41 fe 04 16 fe 01 2b 01 16 13 0a 11 0a 13 0c 11 0c 2c 42 11 09 1f 5a fe 02 13 ?? 11 ?? 13 0f 11 0f 2c 16 11 09 1f 5a da 13 10 1f 40 11 10 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YT_2147741055_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YT!MTB"
        threat_id = "2147741055"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 0f 00 fe 16 ?? ?? ?? 01 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 9a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a d2 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YU_2147741056_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YU!MTB"
        threat_id = "2147741056"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 06 0a 06 7b ?? ?? ?? 04 14 fe 01 0d 09 ?? ?? 00 06 7b ?? ?? ?? 04 28 ?? ?? ?? 06 13 04 06 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 7d ?? ?? ?? 04 00 06 7b ?? ?? ?? 04 28 ?? ?? ?? 0a 0b 07 14 72 ?? ?? ?? 70 16 8d ?? ?? ?? 01 14 14 28 ?? ?? ?? 0a 0c 08 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 14 14 28 ?? ?? ?? 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {13 04 11 04 11 04 47 02 09 1f 10 5d 91 61 d2 52 00 09 17 d6 0d 09 08 fe 02 16 fe 01 13 05 11 05 2d d6 06 13 06 2b 00 11 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YV_2147741297_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YV!MTB"
        threat_id = "2147741297"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 10 5d 91 61 d2 52 00 ?? 17 d6 ?? ?? ?? fe 02 16 fe 01 13 ?? 11 ?? 2d ?? 06 13 ?? 2b 00 11 ?? 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {14 fe 01 0d 09 ?? ?? 00 06 7b ?? ?? ?? 04 28 ?? ?? ?? 06 13 04 06 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 7d ?? ?? ?? 04 00 06 7b ?? ?? ?? 04 28 ?? ?? ?? 0a 0b 07 14 72 ?? ?? ?? 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YX_2147741342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YX!MTB"
        threat_id = "2147741342"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 38 ?? ?? ?? 00 00 16 0c 2b ?? 00 02 07 08 6f ?? ?? ?? 0a 0d 02 16 16 6f ?? ?? ?? 0a 13 04 09 11 04 28 ?? ?? ?? 0a 13 ?? 11 ?? 2c ?? 00 17 8d ?? ?? ?? 01 13 ?? 11 ?? 16 12 ?? 28 ?? ?? ?? 0a 9c 06 19 8d ?? ?? ?? 01 25 16 12 ?? 28 ?? ?? ?? 0a 9c 25 17 12 ?? 28 ?? ?? ?? 0a 9c 25 18 11 ?? 16 91 9c 6f ?? ?? ?? 0a 00 00 00 08 17 58 0c 08 02 6f ?? ?? ?? 0a 17 59 fe 02 16 fe 01 13 ?? 11 ?? 2d ?? 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a 17 59 fe 02 16 fe 01 13 ?? 11 ?? 3a ?? ?? ?? ff 06 d0 ?? ?? ?? 01 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 13 ?? 2b ?? 11 ?? 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YY_2147741437_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YY!MTB"
        threat_id = "2147741437"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 16 7e ?? ?? ?? 04 a4 ?? ?? ?? 01 06 17 7e ?? ?? ?? 04 a4 ?? ?? ?? 01 06 18 7e ?? ?? ?? 04 a4 ?? ?? ?? 01 06 19 7e ?? ?? ?? 04 a4 ?? ?? ?? 01 06 1a 7e ?? ?? ?? 04 a4 ?? ?? ?? 01 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 06 dd ?? ?? ?? 00 26 dd ?? ?? ?? 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_YZ_2147741873_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.YZ!MTB"
        threat_id = "2147741873"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 5d 91 06 03 7e ?? ?? ?? 04 8e 69 5d 58 03 5f 61 d2 61 d2 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_BB_2147742025_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.BB!MTB"
        threat_id = "2147742025"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 1f 10 da 17 da 17 d6 8d ?? ?? ?? 01 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 1b 8d ?? ?? ?? 01 25 16 02 a2 25 17 1f 10 8c ?? ?? ?? 01 a2 25 18 06 a2 25 19 16 8c ?? ?? ?? 01 a2 25 1a 06 8e 69 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 06 26 06 8e 69 17 da 0b 16 0c 2b [0-2] 06 08 8f ?? ?? ?? 01 0d 09 09 47 02 08 1f 10 5d 91 61 d2 52 [0-1] 08 17 d6 0c 08 07 fe 02 16 fe [0-6] 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_PB_2147742744_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.PB!MTB"
        threat_id = "2147742744"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 50 79 5a 74 79 61 00 00 [0-32] 41 50 79 5a 74 79 61 20 49 6e 63 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "FgBJFXTh.exe" ascii //weight: 1
        $x_1_3 = "SkipVerification" ascii //weight: 1
        $x_1_4 = "sQOmgfaWJyGxRyyLlfEb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_PC_2147742835_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.PC!MTB"
        threat_id = "2147742835"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XorDecrypt" ascii //weight: 1
        $x_1_2 = "PolyVDecrypt" ascii //weight: 1
        $x_1_3 = "DecryptBitmap" ascii //weight: 1
        $x_1_4 = "DecryptImage" ascii //weight: 1
        $x_1_5 = "DecryptionKeyI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_PD_2147742836_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.PD!MTB"
        threat_id = "2147742836"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiTaskManagerKill" ascii //weight: 1
        $x_1_2 = "svchost.exe" ascii //weight: 1
        $x_1_3 = "$6110692e-f532-4c69-8751-27f9b4d3fa6e" ascii //weight: 1
        $x_1_4 = "svchost.Resources" wide //weight: 1
        $x_1_5 = "GetProcessesByName" ascii //weight: 1
        $x_1_6 = "get_FileName" ascii //weight: 1
        $x_1_7 = "v2.0.50727" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_PE_2147743105_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.PE!MTB"
        threat_id = "2147743105"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NoLove.exe" ascii //weight: 1
        $x_1_2 = "No-Love" wide //weight: 1
        $x_1_3 = "cmd.exe /c ping 0 -n 2 & del \"\"" wide //weight: 1
        $x_1_4 = "NoLove" wide //weight: 1
        $x_1_5 = "127.0.0.1" wide //weight: 1
        $x_1_6 = "SystemDrive" wide //weight: 1
        $x_1_7 = "Executed As" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_PG_2147743280_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.PG!MTB"
        threat_id = "2147743280"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\screenshot.jpg" wide //weight: 1
        $x_1_2 = "https://api.ipify.org" wide //weight: 1
        $x_1_3 = "Beds-Protector-The-Quick-Brown-Fox-Jumped-Over-The-Lazy-Dog" ascii //weight: 1
        $x_1_4 = "Stealer_build.exe" wide //weight: 1
        $x_1_5 = "\\Chrome32.txt" wide //weight: 1
        $x_1_6 = "http://goo.gl/YroZm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_AP_2147743721_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.AP!MTB"
        threat_id = "2147743721"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ClientPlugin\\obj\\Release\\ClientPlugin.pdb" ascii //weight: 1
        $x_1_2 = "ClientPlugin.dll" ascii //weight: 1
        $x_1_3 = "$1d4cc0d7-4b4b-4f30-a4e1-71be2e6d0299" ascii //weight: 1
        $x_1_4 = "IClientMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_AD_2147743924_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.AD!MTB"
        threat_id = "2147743924"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tupeu.dll" ascii //weight: 1
        $x_1_2 = "swety" ascii //weight: 1
        $x_1_3 = "csharpstub" ascii //weight: 1
        $x_1_4 = "Clubbing" ascii //weight: 1
        $x_1_5 = "sety" ascii //weight: 1
        $x_1_6 = "5.21.1.32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_MSIL_CryptInject_PH_2147744926_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.PH!MTB"
        threat_id = "2147744926"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LinkZip.dll" wide //weight: 1
        $x_1_2 = "Assembly for DotNetToJScript" ascii //weight: 1
        $x_1_3 = "James Forshaw" ascii //weight: 1
        $x_1_4 = "%temp%" wide //weight: 1
        $x_1_5 = "bd.hta" wide //weight: 1
        $x_1_6 = "mshta.exe" wide //weight: 1
        $x_1_7 = "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest." wide //weight: 1
        $x_1_8 = "finalUrl" ascii //weight: 1
        $x_1_9 = "DownloadData" ascii //weight: 1
        $x_1_10 = "avUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_AV_2147747984_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.AV!MTB"
        threat_id = "2147747984"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\exe1.exe" wide //weight: 1
        $x_1_2 = "\\exe2.exe" wide //weight: 1
        $x_1_3 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 [0-16] 5c 00 74 00 65 00 6d 00 70 00 6c 00 65 00 72 00 73 00 [0-16] 76 00 69 00 6a 00 6f 00 79 00}  //weight: 1, accuracy: Low
        $x_1_4 = "costura.icsharpcode.sharpziplib.dll.compressed" wide //weight: 1
        $x_1_5 = "costura.icsharpcode.sharpziplib.pdb.compressed" wide //weight: 1
        $x_1_6 = "costura.costura.dll.compressed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_AW_2147748495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.AW!MTB"
        threat_id = "2147748495"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_Encrypted" ascii //weight: 1
        $x_1_2 = "StealDB.exe" ascii //weight: 1
        $x_1_3 = "Encrypted" wide //weight: 1
        $x_1_4 = "\\Pass.txt" wide //weight: 1
        $x_1_5 = "RC2Decrypt" ascii //weight: 1
        $x_1_6 = "StealDB.My" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_BA_2147750062_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.BA!MTB"
        threat_id = "2147750062"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eazfuscator.NET" wide //weight: 1
        $x_1_2 = "Software\\Gapotchenko\\" wide //weight: 1
        $x_1_3 = "Spotify Checker.exe" ascii //weight: 1
        $x_1_4 = "Combo.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptInject_BF_2147755573_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptInject.BF!MTB"
        threat_id = "2147755573"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FaultCodeNymKFGrypG" ascii //weight: 1
        $x_1_2 = "KeywordsBLA" ascii //weight: 1
        $x_1_3 = "RenewOnCallTime" ascii //weight: 1
        $x_1_4 = "TargetThBWLK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


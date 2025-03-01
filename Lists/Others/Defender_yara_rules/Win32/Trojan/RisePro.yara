rule Trojan_Win32_RisePro_CCDY_2147896436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.CCDY!MTB"
        threat_id = "2147896436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 0d ?? fe ff ff 50 e8 ?? ?? ?? ?? 88 84 0d ?? ?? ?? ?? 41 83 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 45 08 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_AMAB_2147897524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.AMAB!MTB"
        threat_id = "2147897524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 4c 9d 00 91 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 89 4c 24 28 85 d2 75 ?? f6 c3 01 74 ?? 8d 47 fd 3b d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_GNF_2147897701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.GNF!MTB"
        threat_id = "2147897701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {32 cb d0 c1 80 c1 01 80 f1 3e 80 c1 04 f6 d9 32 d9 8d 4c 0c 08 88 11 8d 64 24 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_CCEU_2147897764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.CCEU!MTB"
        threat_id = "2147897764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8b 4d fc 89 85 ?? fe ff ff 8d [0-5] 89 8d ?? fe ff ff c5 fe 6f 85 ?? fe ff ff c5 fd ef [0-5] 50 c5 fd 7f [0-5] 57 c5 f8 77 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_CCHF_2147901795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.CCHF!MTB"
        threat_id = "2147901795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b 15 ?? ?? ?? ?? 32 c8 8b 3d ?? ?? ?? ?? 88 4d e8 3b d7 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_KAA_2147902107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.KAA!MTB"
        threat_id = "2147902107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b 15 ?? ?? ?? ?? 32 c8 8b 3d ?? ?? ?? ?? 88 4d dc 3b d7 73 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_EM_2147902581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.EM!MTB"
        threat_id = "2147902581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F\\1D23E801FF916F1C-DF69CE3484AE41BB1" ascii //weight: 1
        $x_1_2 = "Software\\Enigma Protector\\BB3DF1FDBB935E9B-50AFA6E27F8A32AF" ascii //weight: 1
        $x_1_3 = "enigma_ide.dll" ascii //weight: 1
        $x_1_4 = "c:\\debug.log" ascii //weight: 1
        $x_1_5 = "DLL_Loader.dll" ascii //weight: 1
        $x_1_6 = "EP_CheckUpStartupPasswordHashString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_DB_2147903313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.DB!!Risepro.gen!MTB"
        threat_id = "2147903313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "Risepro: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Telegram: https://t.me/RiseProSUPPORT" ascii //weight: 1
        $x_1_2 = "ipinfo.io" ascii //weight: 1
        $x_1_3 = "maxmind.com/en/locate-my-ip-address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_KAB_2147903840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.KAB!MTB"
        threat_id = "2147903840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dekmtndfa" ascii //weight: 1
        $x_1_2 = "mbamngjjb" ascii //weight: 1
        $x_1_3 = "hqnhakjac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_RP_2147904789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.RP!MTB"
        threat_id = "2147904789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\WinLicense" ascii //weight: 1
        $x_1_2 = "StealerClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_RP_2147904789_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.RP!MTB"
        threat_id = "2147904789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\WinLicense" ascii //weight: 1
        $x_1_2 = "\\\\.\\SIWVID" ascii //weight: 1
        $x_1_3 = "oreans32.sys" ascii //weight: 1
        $x_1_4 = "oreansx64.sys" ascii //weight: 1
        $x_1_5 = "HARDWARE\\ACPI\\DSDT\\VBOX__" ascii //weight: 1
        $x_1_6 = "heidisql.exe" wide //weight: 1
        $x_1_7 = "Ansgar Becker, see gpl.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_RP_2147904789_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.RP!MTB"
        threat_id = "2147904789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 74 61 67 67 61 6e 74 00 30 00 00 00 ?? ?? ?? ?? 22 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\\\.\\Global\\oreansx64" ascii //weight: 1
        $x_1_3 = "Please, contact the software developers with the following codes. Thank you." ascii //weight: 1
        $x_1_4 = "Please, contact yoursite@yoursite.com. Thank you!" ascii //weight: 1
        $x_1_5 = {04 64 a0 59 40 05 ce 0a 40 05 ce 0a 40 05 ce 0a 1b 6d cd 0b 51 05 ce 0a 1b 6d cb 0b e0 05 ce 0a 95 68 ca 0b 52 05 ce 0a 95 68 cd 0b 57 05 ce 0a 95 68 cb 0b 35 05 ce 0a 1b 6d ca 0b 55 05 ce 0a 1b 6d cf 0b 53 05 ce 0a 40 05 cf 0a 94 05 ce 0a db 6b c7 0b 41 05 ce 0a db 6b 31 0a 41 05 ce 0a db 6b cc 0b 41 05 ce 0a 52 69 63 68 40 05 ce 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_RP_2147904789_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.RP!MTB"
        threat_id = "2147904789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WLNumDLLsProt" ascii //weight: 1
        $x_1_2 = "\\\\.\\Global\\oreansx64" ascii //weight: 1
        $x_1_3 = "XprotEvent" ascii //weight: 1
        $x_1_4 = "Software\\WinLicense" ascii //weight: 1
        $x_1_5 = "RestartApp.exe" ascii //weight: 1
        $x_10_6 = {2a 52 e4 13 6e 33 8a 40 6e 33 8a 40 6e 33 8a 40 35 5b 89 41 60 33 8a 40 35 5b 8f 41 f0 33 8a 40 bb 5e 8e 41 7c 33 8a 40 bb 5e 89 41 7a 33 8a 40 bb 5e 8f 41 1b 33 8a 40 35 5b 8e 41 7a 33 8a 40 35 5b 8b 41 7d 33 8a 40 6e 33 8b 40 ba 33 8a 40 f5 5d 83 41 6f 33 8a 40 f5 5d 75 40 6f 33 8a 40 f5 5d 88 41 6f 33 8a 40 52 69 63 68 6e 33 8a 40}  //weight: 10, accuracy: High
        $x_10_7 = {04 64 a0 59 40 05 ce 0a 40 05 ce 0a 40 05 ce 0a 1b 6d cd 0b 51 05 ce 0a 1b 6d cb 0b e0 05 ce 0a 95 68 ca 0b 52 05 ce 0a 95 68 cd 0b 57 05 ce 0a 95 68 cb 0b 35 05 ce 0a 1b 6d ca 0b 55 05 ce 0a 1b 6d cf 0b 53 05 ce 0a 40 05 cf 0a 94 05 ce 0a db 6b c7 0b 41 05 ce 0a db 6b 31 0a 41 05 ce 0a db 6b cc 0b 41 05 ce 0a 52 69 63 68 40 05 ce 0a}  //weight: 10, accuracy: High
        $x_10_8 = {6a 99 1d e4 2e f8 73 b7 2e f8 73 b7 2e f8 73 b7 65 80 70 b6 25 f8 73 b7 65 80 76 b6 ee f8 73 b7 65 80 74 b6 2f f8 73 b7 ec 79 8e b7 2a f8 73 b7 ec 79 77 b6 3d f8 73 b7 ec 79 70 b6 34 f8 73 b7 ec 79 76 b6 75 f8 73 b7 65 80 77 b6 36 f8 73 b7 65 80 75 b6 2f f8 73 b7 65 80 72 b6 35 f8 73 b7 2e f8 72 b7 0e f9 73 b7 dd 7a 7a b6 32 f8 73 b7 dd 7a 8c b7 2f f8 73 b7 2e f8 e4 b7 2f f8 73 b7 dd 7a 71 b6 2f f8 73 b7 52 69 63 68 2e f8 73 b7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RisePro_RP_2147904789_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.RP!MTB"
        threat_id = "2147904789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "WLNumDLLsProt" ascii //weight: 5
        $x_5_2 = "\\\\.\\Global\\oreansx64" ascii //weight: 5
        $x_5_3 = "XprotEvent" ascii //weight: 5
        $x_5_4 = "Software\\WinLicense" ascii //weight: 5
        $x_10_5 = {a4 6b 87 80 e0 0a e9 d3 e0 0a e9 d3 e0 0a e9 d3 ab 72 ea d2 eb 0a e9 d3 ab 72 ec d2 20 0a e9 d3 ab 72 ee d2 e1 0a e9 d3 22 8b 14 d3 e4 0a e9 d3 22 8b ed d2 f3 0a e9 d3 22 8b ea d2 f8 0a e9 d3 22 8b ec d2 b6 0a e9 d3 ab 72 ed d2 f8 0a e9 d3 ab 72 ef d2 e1 0a e9 d3 ab 72 e8 d2 fb 0a e9 d3 e0 0a e8 d3 f9 0b e9 d3 13 88 e0 d2 fc 0a e9 d3 13 88 e9 d2 e1 0a e9 d3 13 88 16 d3 e1 0a e9 d3 e0 0a 7e d3 e1 0a e9 d3 13 88 eb d2 e1 0a e9 d3 52 69 63 68 e0 0a e9 d3}  //weight: 10, accuracy: High
        $x_10_6 = {a4 6d 87 80 e0 0c e9 d3 e0 0c e9 d3 e0 0c e9 d3 ab 74 ea d2 eb 0c e9 d3 ab 74 ec d2 20 0c e9 d3 ab 74 ee d2 e1 0c e9 d3 22 8d 14 d3 e4 0c e9 d3 22 8d ed d2 f3 0c e9 d3 22 8d ea d2 f8 0c e9 d3 22 8d ec d2 b6 0c e9 d3 ab 74 ed d2 f8 0c e9 d3 ab 74 ef d2 e1 0c e9 d3 ab 74 e8 d2 fb 0c e9 d3 e0 0c e8 d3 fa 0d e9 d3 13 8e e0 d2 fc 0c e9 d3 13 8e e9 d2 e1 0c e9 d3 13 8e 16 d3 e1 0c e9 d3 e0 0c 7e d3 e1 0c e9 d3 13 8e eb d2 e1 0c e9 d3 52 69 63 68 e0 0c e9 d3}  //weight: 10, accuracy: High
        $x_50_7 = "StealerClient" ascii //weight: 50
        $x_1_8 = {56 50 53 e8 01 00 00 00 00 58 89 c3 40 2d 00 ?? ?? 00 2d 44 17 0c 10 05 3b 17 0c 10 80 3b cc 75}  //weight: 1, accuracy: Low
        $x_1_9 = "MSBuild.exe" wide //weight: 1
        $x_1_10 = "RAIDXpert2.exe" wide //weight: 1
        $x_1_11 = "KVM Vision Viewer.exe" wide //weight: 1
        $x_1_12 = "filezilla.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 4 of ($x_5_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RisePro_HNS_2147904848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.HNS!MTB"
        threat_id = "2147904848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 06 01 1e 83 c6 04 49 eb f2 5e 59 5b 58}  //weight: 1, accuracy: High
        $x_1_2 = {6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 00 00 00 00 36 00 07 00 01 00 46 00 69 00 6c}  //weight: 1, accuracy: High
        $x_1_3 = {4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 a9 00 20 00 20 00 32 00 30 00 32 00 33}  //weight: 1, accuracy: High
        $x_1_4 = {46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 6f 00 66 00 66 00 44 00 65 00 66 00 2e 00 65 00 78 00 65 00 00 00 00 00 2e 00 07 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 6f 00 66 00 66 00 44 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_EC_2147905670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.EC!MTB"
        threat_id = "2147905670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 00 00 3e 00 0f 00 01 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00 2e 00 39 00 31 00 34 00 39}  //weight: 2, accuracy: High
        $x_2_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 2e 00 4e 00 45 00 54 00 20 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 00 00 00 00 42 00 0f 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00 2e 00 39 00 31 00 34 00 39}  //weight: 2, accuracy: High
        $x_1_3 = "Make sure that this file is not being used by another program" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_EC_2147905670_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.EC!MTB"
        threat_id = "2147905670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yoursite@yoursite.com. Thank you!" ascii //weight: 1
        $x_1_2 = "4IFSMGR  VKD     VMM     VWIN32  VXDLD" ascii //weight: 1
        $x_1_3 = "Make sure that this file is not being used by another program" ascii //weight: 1
        $x_2_4 = {20 20 20 00 20 20 20 20 00 50 06 00 00 10 00 00 00 d6 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 88 03 00 00 00 60 06 00 00 04 00 00 00 e6 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 70 06 00 00 02 00 00 00 ea 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_GPB_2147907052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.GPB!MTB"
        threat_id = "2147907052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 01 8d 48 ?? 30 4c 05 ?? 40 83 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_YAB_2147908346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.YAB!MTB"
        threat_id = "2147908346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b f3 ff 45 ?? 66 0f a4 c3 ?? 0f b7 3c 0f 0f c9 80 e1 0a 0f b7 df d3 c9 66 d3 f9 8b c8 f9 c1 e9 0b f6 c7 3e 66 85 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RisePro_LZ_2147927193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RisePro.LZ!MTB"
        threat_id = "2147927193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 50 06 00 00 10 00 00 00 ae 03 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 38 83 00 00 00 60 06 00 00 3c 00 00 00 be 03 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


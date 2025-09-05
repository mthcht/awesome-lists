rule Ransom_Win32_Conti_PA_2147750005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.PA!MTB"
        threat_id = "2147750005"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CONTI_README.txt" wide //weight: 1
        $x_1_2 = "Your system is LOCKED. Write us on the emails" ascii //weight: 1
        $x_1_3 = "DO NOT TRY to decrypt files using other software." ascii //weight: 1
        $x_1_4 = "@protonmail.com" ascii //weight: 1
        $x_1_5 = ".CONTI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_SW_2147759451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.SW!MSR"
        threat_id = "2147759451"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The network is LOCKED" ascii //weight: 1
        $x_1_2 = "Do not try to use other software. For decryption KEY write HERE" ascii //weight: 1
        $x_1_3 = "flapalinta1950@protonmail.com" ascii //weight: 1
        $x_1_4 = "xersami@protonmail.com" ascii //weight: 1
        $x_1_5 = "HOW_TO_DECRYPT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_SD_2147763043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.SD!MTB"
        threat_id = "2147763043"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aaa_TouchMeNot_\\aaa_TouchMeNot_.txt" ascii //weight: 1
        $x_1_2 = "CONTI_README.txt" ascii //weight: 1
        $x_1_3 = "cmd.exe /c net stop VeeamBrokerSvc /y" ascii //weight: 1
        $x_1_4 = "cmd.exe /c net stop mfefire /y" ascii //weight: 1
        $x_1_5 = "cmd.exe /c net stop SQLAgent$CITRIX_METAFRAME /y" ascii //weight: 1
        $x_1_6 = "cmd.exe /c net stop VeeamEnterpriseManagerSvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_A_2147764700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.A!MTB"
        threat_id = "2147764700"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\CONTI_README.txt" ascii //weight: 1
        $x_1_2 = "The system is LOCKED. Do not try to unlock with other software. For KEY write on emails:" ascii //weight: 1
        $x_1_3 = "\\aaa_TouchMeNot_.txt" ascii //weight: 1
        $x_1_4 = {8a 84 1d f0 [0-4] 34 ?? 88 84 1d [0-4] 43 83 fb ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_2147765127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti!MTB"
        threat_id = "2147765127"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 01 ac}  //weight: 1, accuracy: High
        $x_1_2 = {aa 4a 0f 85 ?? ?? ff ff 8b ec 5d c2 0c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {32 c1 2a c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_MK_2147771114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.MK!MTB"
        threat_id = "2147771114"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "conti_v3\\Release\\cryptor.pdb" ascii //weight: 5
        $x_5_2 = "If you try to use any additional recovery software - the files might be damaged or lost" ascii //weight: 5
        $x_5_3 = "To make sure that we REALLY CAN recover data - we offer you to decrypt samples" ascii //weight: 5
        $x_5_4 = "contirecovery.info" ascii //weight: 5
        $x_5_5 = "YOU SHOULD BE AWARE!" ascii //weight: 5
        $x_5_6 = "We've downloaded your data and are ready to publish it on out news website if you do not respond" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Conti_ZZ_2147771172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.ZZ!MTB"
        threat_id = "2147771172"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 f8 0f b6 9f ?? ?? ?? 00 0f b6 04 31 03 da 03 c3 99 bb ?? ?? ?? ?? f7 fb 8a 04 31 83 c7 01 0f b6 d2 8a 1c 0a 88 1c 31 88 04 0a 8b c7 25 ?? ?? ?? ?? 79 05 48 83 c8 c0 40 83 c6 01 81 fe 01 7c bb}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 46 01 99 be ?? ?? ?? ?? f7 fe bb 00 83 c5 01 0f b6 f2 0f b6 04 0e 03 c7 88 54 24 12 99 bf 00 f7 ff 8a 04 0e 0f b6 fa 88 54 24 13 0f b6 14 0f 88 14 0e 88 04 0f 0f b6 14 0f 0f b6 04 0e 03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 30 55 ff 83 6c 24 14 01 75 a6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_RQ_2147773373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.RQ!MTB"
        threat_id = "2147773373"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files are currently encrypted by CONTI strain" ascii //weight: 1
        $x_1_2 = "https://contirecovery.best" ascii //weight: 1
        $x_1_3 = "http://contirecj4hbzmyzuydyzrvm2c65blmvhoj2cvf25zqj2dwrrqcq5oad.onion" ascii //weight: 1
        $x_1_4 = "YOU SHOULD BE AWARE!" ascii //weight: 1
        $x_1_5 = "Just in case, if you try to ignore us. We've downloaded your data and are ready to publish it on out news website if you do not respond. So it will be better for both sides if you contact us ASAP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Conti_RJ_2147774345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.RJ!MTB"
        threat_id = "2147774345"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "expand 32-byte kexpand 16-byte kstring too long" ascii //weight: 1
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "@protonmail.com" ascii //weight: 1
        $x_1_4 = "iphlpapi.pdb" ascii //weight: 1
        $x_1_5 = "CryptImportKey" ascii //weight: 1
        $x_1_6 = "DecryptFileA" ascii //weight: 1
        $x_1_7 = "GetSystemInfo" ascii //weight: 1
        $x_1_8 = "Volume Shadow Copy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_MB_2147776538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.MB!MTB"
        threat_id = "2147776538"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 0a 95 e9 d1 5b 83 c2 [0-1] 69 ff [0-4] 8b c1 c1 e8 [0-1] 33 c1 69 c8 01 33 f9 83 eb 01 75}  //weight: 10, accuracy: Low
        $x_10_2 = "expand 32-byte k" ascii //weight: 10
        $x_10_3 = "expand 16-byte k" ascii //weight: 10
        $x_5_4 = ".JVUAE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_ZC_2147780277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.ZC"
        threat_id = "2147780277"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 01 83 c1 04 89 02 83 c2 04 83 ef 01 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {8a 01 8d 49 01 88 44 0a ff 83 ef 01 75 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8a 01 88 04 0a 41 83 ef 01 75 f5}  //weight: 1, accuracy: High
        $x_1_4 = {69 0a 95 e9 d1 5b 83 c2 04 69 ff 95 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 95 e9 d1 5b 33 f9 83 eb 01 75 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Conti_ZD_2147780278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.ZD"
        threat_id = "2147780278"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 e0 89 45 94 8b 45 e4 89 45 98 8b 45 e8 89 45 9c 8b 45 ec 89 45 a0 8b 45 f0 89 45 a4 8b 45 f4 89 45 a8 8b 45 f8 89 45 ac 8b 85 60 ff ff ff 89 4d b0 89 4d b4 8d 4d 80 89 45 b8 8b 85 5c ff ff ff 56 57 c7 45 80 65 78 70 61 c7 45 84 6e 64 20 33 c7 45 88 32 2d 62 79 c7 45 8c 74 65 20 6b 89 45 bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_ZE_2147780279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.ZE"
        threat_id = "2147780279"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 15 00 00 00 c7 45 ec b9 07 a2 25 c7 45 f0 f3 dd 60 46 c7 45 f4 8e e9 76 e5 c7 45 f8 8c 74 06 3e e8 ?? ?? ?? ?? 83 c4 08 8d 4d e8 6a 00 6a 00 51 6a 04 68 ?? ?? ?? ?? 6a 10 8d 4d ec 51 68 06 00 00 c8 56 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_A_2147780280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.A!!Conti.A"
        threat_id = "2147780280"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "Conti: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 01 83 c1 04 89 02 83 c2 04 83 ef 01 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {8a 01 8d 49 01 88 44 0a ff 83 ef 01 75 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8a 01 88 04 0a 41 83 ef 01 75 f5}  //weight: 1, accuracy: High
        $x_1_4 = {69 0a 95 e9 d1 5b 83 c2 04 69 ff 95 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 95 e9 d1 5b 33 f9 83 eb 01 75 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Conti_ZA_2147781373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.ZA"
        threat_id = "2147781373"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 01 83 c1 04 89 02 83 c2 04 83 ee 01 75 f1}  //weight: 10, accuracy: High
        $x_10_3 = {8a 01 8d 49 01 88 44 0a ff 83 ee 01 75 f2}  //weight: 10, accuracy: High
        $x_10_4 = {8b c1 c1 e8 18 33 c1 69 f8 95 e9 d1 5b 69 c6 95 e9 d1 5b be 03 00 00 00 33 f8 8b ?? ?? 99 f7 fe 8b ?? ?? 85 d2 74 40 00 69 ?? 95 e9 d1 5b c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_MAK_2147787227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.MAK!MTB"
        threat_id = "2147787227"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 06 8d 76 01 0f b6 c0 83 e8 [0-1] 6b c0 [0-1] 99 f7 fb 8d 42 [0-1] 99 f7 fb 88 56 ff 83 ef 01 75}  //weight: 10, accuracy: Low
        $x_1_2 = "expand 32-byte k" ascii //weight: 1
        $x_1_3 = "expand 16-byte k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_MBK_2147798264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.MBK!MTB"
        threat_id = "2147798264"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 0f 44 c8 88 0e 33 c9 41 81 f9 [0-4] 72 30 00 69 c1 [0-4] 33 d2 2d [0-4] 0f af c1 f7 f3 85 d2 0f b6 ca 8d 42}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_AC_2147805765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.AC!MTB"
        threat_id = "2147805765"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 06 c0 e0 ?? 0a c8 c0 e1 ?? 8a 46 ?? 24 ?? 0a c8 88 0c ?? 42 8d 76 ?? 81 fa ?? ?? ?? ?? 7d ?? 8b 30 00 8a 4e ?? 80 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_ZF_2147806336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.ZF"
        threat_id = "2147806336"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8d 45 f8 50 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 c4 04}  //weight: 10, accuracy: Low
        $x_10_3 = {68 00 10 00 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 c4 04}  //weight: 10, accuracy: Low
        $x_10_4 = {8b 0e 03 ca 33 d2 38 11 74 0d 66 0f 1f 44 00 00 42 80 3c 0a 00 75 f9 51 e8 ?? ?? ?? ?? 83 c4 04 3b 45 f4 74 24 8b 45 fc 47 8b 55 f8 83 c6 04 83 c3 02 3b 78 18 72 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_ZG_2147806337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.ZG"
        threat_id = "2147806337"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_50_2 = {8d 04 5b c7}  //weight: 50, accuracy: High
        $x_50_3 = {8d 34 c5 95 e9 d1 5b}  //weight: 50, accuracy: High
        $x_50_4 = {75 15 0f b6 4a 02 c1 e1 10 1a 00 33 c9 [0-1] 83 ?? 01 74 1a 83 ?? 01 74 0c 83 ?? 01}  //weight: 50, accuracy: Low
        $x_50_5 = {0f b6 42 01 c1 e0 08 33 c8 0f b6 02 33 c8}  //weight: 50, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_IPA_2147811696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.IPA!MTB"
        threat_id = "2147811696"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 2b c8 6b c1 ?? 99 f7 ff 8d 42 7f 99 f7 ff 88 94 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_AB_2147812000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.AB!MTB"
        threat_id = "2147812000"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DnD Files" wide //weight: 1
        $x_1_2 = "*.dnd" wide //weight: 1
        $x_1_3 = "DnD.Document" wide //weight: 1
        $x_1_4 = {76 08 3b f8 0f 82 78 01 00 00 f7 c7 03 00 00 00 75 14 c1 e9 02 83 e2 03 83 f9 08 72 29 f3 a5}  //weight: 1, accuracy: High
        $x_1_5 = {8d 48 17 83 e1 f0 89 4d f0 c1 f9 04 49 83 f9 20 7d 0e 83 ce ff d3 ee 83 4d f8 ff 89 75 f4 eb 10 83 c1 e0 83 c8 ff 33 f6 d3 e8 89 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_AD_2147814066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.AD!MTB"
        threat_id = "2147814066"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 39 00 75 ?? 53 56 57 bf ?? 00 00 00 8d 71 01 8d 5f ?? 8a 06 8d 76 01 0f b6 c0 83 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {99 f7 fb 8d 42 ?? 99 f7 fb 88 56 ff 83 ef 01 75 ?? 5f 5e 5b 8d 41 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_WEN_2147817049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.WEN!MTB"
        threat_id = "2147817049"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 66 c7 45 90 74 00 30 5c 05 85 40 83 f8 0c 73 05 8a 5d 84}  //weight: 1, accuracy: High
        $x_1_2 = {30 8c 05 75 ff ff ff 40 83 f8 0c 73 08 8a 8d 74}  //weight: 1, accuracy: High
        $x_1_3 = {88 5d e0 32 f0 88 65 e1 32 f8 88 75 e3 b1 7f 88 7d e4 32 c8 c6 45 e6 00 b5 25 88 4d de 32 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Conti_PLD_2147817050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.PLD!MTB"
        threat_id = "2147817050"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 98 66 31 44 4d 9a 41 83 f9 2f 73 05 8a 45 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_FF_2147830856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.FF!MTB"
        threat_id = "2147830856"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {8a 06 8d 76 01 0f b6 c0 83 e8 67 6b c0 25 99 f7 fb 8d 42 7f 99 f7 fb 88 56 ff 83 ef}  //weight: 30, accuracy: High
        $x_30_2 = {8a 07 8d 7f 01 0f b6 c8 83 e9 31 8d 04 cd 00 00 00 00 2b c1 c1 e0 02 99 f7 fe 8d 42 7f 99 f7 fe 88 57 ff 83 e8}  //weight: 30, accuracy: High
        $x_30_3 = {8a 07 8d 7f 01 0f b6 c0 b9 1a 00 00 00 2b c8 8b c1 c1 e0 05 2b c1 03 c0 99 f7 fe 8d 42 7e 99 f7 fe 88 57 ff 83}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Conti_LKV_2147846615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.LKV!MTB"
        threat_id = "2147846615"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All of your files are currently encrypted by CONTI ransomware" wide //weight: 1
        $x_1_2 = "R@ns0mw4r3Key" wide //weight: 1
        $x_1_3 = ".l0ck3d" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-255] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_5 = "R3ADM3.txt" wide //weight: 1
        $x_1_6 = "(you should download and install TOR browser first https://torproject.org)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Conti_MKZ_2147951590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Conti.MKZ!MTB"
        threat_id = "2147951590"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "All exfiltrated data published on darknet forums" ascii //weight: 3
        $x_3_2 = "vssadmin delete shadows /all /quiet" ascii //weight: 3
        $x_2_3 = "RECOVER_INSTRUCTIONS.html" ascii //weight: 2
        $x_3_4 = "Contact ONLY after payment confirmation" ascii //weight: 3
        $x_2_5 = "COMPROMISED" ascii //weight: 2
        $x_2_6 = "DisableRealtimeMonitoring" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


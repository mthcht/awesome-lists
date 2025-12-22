rule Ransom_Win64_FileCoder_DR_2147763522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.DR!MSR"
        threat_id = "2147763522"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decrypt the files or bruteforce the key will be futile and lead to loss of time and precious data" ascii //weight: 1
        $x_1_2 = "Go build ID:" ascii //weight: 1
        $x_1_3 = "-----BEGIN RSA PUBLIC KEY-----" ascii //weight: 1
        $x_1_4 = "PASSWORD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AB_2147766648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AB!MTB"
        threat_id = "2147766648"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 56 48 83 ec 20 48 8b f1 4c 8d 35 0d 58 ff ff 8b ea 44 8b d2 83 e5 04 41 81 e2 80 00 00 00 44 8b ca 41 8b f8 41 83 c9 01 f6 c2 40 44 0f 44 ca}  //weight: 1, accuracy: High
        $x_1_2 = {83 c9 02 41 f6 c1 08 41 0f 44 c9 45 33 c0 81 e1 3b ff ff ff 85 d2}  //weight: 1, accuracy: High
        $x_1_3 = {75 10 48 c1 c1 10 66 f7 c1 ff ff 75 01 c3 48 c1 c9 10}  //weight: 1, accuracy: High
        $x_1_4 = {4c 8d 35 0d 58 ff ff 8b ea 44 8b d2 83 e5 04 41 81 e2 80 00 00 00 44 8b ca}  //weight: 1, accuracy: High
        $x_1_5 = {f6 c2 40 44 0f 44 ca 8b 15 ef 57 03 00 41 8b c9 83 c9 02 41 f6 c1 08 41 0f 44 c9 45 33 c0 81 e1 3b ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_FileCoder_AB_2147766648_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AB!MTB"
        threat_id = "2147766648"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "s have been encrypted.C:\\Windows\\System32\\svchost.exe" ascii //weight: 3
        $x_3_2 = ".ccl.tmp" ascii //weight: 3
        $x_2_3 = "Best Regards , CCLand" ascii //weight: 2
        $x_2_4 = "C:\\\\Program Files\\\\Windows Defender" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AB_2147766648_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AB!MTB"
        threat_id = "2147766648"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!!README!!!.txt" ascii //weight: 1
        $x_1_2 = "crypted000007" ascii //weight: 1
        $x_1_3 = "\\.no_more_ransom" ascii //weight: 1
        $x_1_4 = "\\tasks\\hddidlescan.job" ascii //weight: 1
        $x_1_5 = "\\aaa_TouchMeNot_.txt" ascii //weight: 1
        $x_1_6 = ".keybtc@gmail_com" ascii //weight: 1
        $x_1_7 = ".paycrypt@gmail_com" ascii //weight: 1
        $x_1_8 = ".wncry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AG_2147808750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AG!MTB"
        threat_id = "2147808750"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 48 8b 9c 24 c8 02 00 00 48 8b 8c 24 d0 02 00 00 48 8d 3d 0e 4f 02 00 be 06 00 00 00 e8 f1 e2 f9 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AG_2147808750_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AG!MTB"
        threat_id = "2147808750"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/wipe" ascii //weight: 1
        $x_1_2 = "VulkaInternetOpenA" ascii //weight: 1
        $x_1_3 = "VulkaFindFirstFileW" ascii //weight: 1
        $x_1_4 = "GENBOTID begin" ascii //weight: 1
        $x_1_5 = "SMBFAST begin" ascii //weight: 1
        $x_1_6 = "pre FINDFILES 1 begin" ascii //weight: 1
        $x_1_7 = "WARNING.TXT" ascii //weight: 1
        $x_1_8 = "KILLPR begin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_CRDA_2147850802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.CRDA!MTB"
        threat_id = "2147850802"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypt_date.txt" ascii //weight: 1
        $x_1_2 = "Peter'sRansomware" ascii //weight: 1
        $x_1_3 = "Elevated!!! Yay" ascii //weight: 1
        $x_1_4 = "Fail to encrypt" ascii //weight: 1
        $x_1_5 = ".7z.rar.m4a.wma.avi.wmv.d3dbsp.sc2save" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AI_2147895173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AI!MTB"
        threat_id = "2147895173"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 49 0f af d1 48 c1 ea ?? 8d 0c 52 89 c2 c1 e1 ?? 29 ca 48 63 d2 41 0f b6 14 13 41 32 14 02 41 88 14 00 48 83 c0 01 48 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_ABC_2147898945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.ABC!MTB"
        threat_id = "2147898945"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 c8 48 8b c1 0f b6 40 01 88 04 24 0f b6 04 24 83 e8 62 6b c0 d9 99 b9 7f 00 00 00 f7 f9 8b c2 83 c0 7f 99 b9 7f 00 00 00 f7 f9 8b c2 48 8b 4c 24 08 48 8b 54 24 20 48 03 d1 48 8b ca 88 41 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_ZC_2147905501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.ZC!MTB"
        threat_id = "2147905501"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MalwareHunterTeam malwrhunterteam Ransomware" ascii //weight: 10
        $x_10_2 = "GPTLocker" ascii //weight: 10
        $x_1_3 = "ComponentResourceManager" ascii //weight: 1
        $x_1_4 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_5 = "BitConverter" ascii //weight: 1
        $x_1_6 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_1_7 = "AesCryptoServiceProvider" ascii //weight: 1
        $x_1_8 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_9 = "BinaryReader" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHB_2147910383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHB!MTB"
        threat_id = "2147910383"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vssadmin" ascii //weight: 1
        $x_1_2 = "Albabat.ekeyAlbabat.keyAlbabat_Searchpersonal_id.txt" ascii //weight: 1
        $x_1_3 = "Your files were encrypted with a KEY" ascii //weight: 1
        $x_1_4 = "BEGIN RSA PUBLIC KEY" ascii //weight: 1
        $x_2_5 = {50 45 00 00 64 86 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 25 00 ?? 0a 00 00 ?? 04 00 00 00 00 00 ?? ?? 0a 00 00 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHF_2147911435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHF!MTB"
        threat_id = "2147911435"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VirtualProtsct" ascii //weight: 1
        $x_1_2 = "VirtualFreeUnmapViewOfFile" ascii //weight: 1
        $x_1_3 = "LdrFindResource" ascii //weight: 1
        $x_1_4 = "cmd /c ping 127.0.0.1" ascii //weight: 1
        $x_1_5 = "heroherohero" ascii //weight: 1
        $x_1_6 = {2e 64 61 74 61 5f 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 61 74 61 5f 30 31}  //weight: 1, accuracy: Low
        $x_2_7 = {50 45 00 00 64 86 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 00 00 ?? 9f 00 00 ?? ?? 00 00 00 00 00 ?? ?? 5e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHE_2147912431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHE!MTB"
        threat_id = "2147912431"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VirtualProtsct" ascii //weight: 1
        $x_1_2 = "VirtualFreeUnmapViewOfFile" ascii //weight: 1
        $x_1_3 = "LdrFindResource" ascii //weight: 1
        $x_1_4 = "cmd /c ping 127.0.0.1" ascii //weight: 1
        $x_1_5 = "heroherohero" ascii //weight: 1
        $x_1_6 = {2e 64 61 74 61 5f 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 61 74 61 5f 30 31}  //weight: 1, accuracy: Low
        $x_2_7 = {50 45 00 00 64 86 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 00 00 24 9f 00 00 de 60 00 00 00 00 00 c4 80 5e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHI_2147913352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHI!MTB"
        threat_id = "2147913352"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "vssadmintaskkillboot" ascii //weight: 1
        $x_1_3 = "XORKeyStream" ascii //weight: 1
        $x_1_4 = "processGetAdaptersInfo" ascii //weight: 1
        $x_1_5 = "mydesktopqos.exe" ascii //weight: 1
        $x_1_6 = "BEGIN PUBLIC KEY" ascii //weight: 1
        $x_1_7 = "syscall.FindNextFile" ascii //weight: 1
        $x_1_8 = "syscall.WriteFile" ascii //weight: 1
        $x_1_9 = "RLocker" ascii //weight: 1
        $x_1_10 = "filesdelete/quietLocker" ascii //weight: 1
        $x_2_11 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 5e 11 00 00 2a 01 00 00 00 00 00 40 5c 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHP_2147914188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHP!MTB"
        threat_id = "2147914188"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VirtualProtsct" ascii //weight: 1
        $x_1_2 = "VirtualFreeUnmapViewOfFile" ascii //weight: 1
        $x_1_3 = "LdrFindResource" ascii //weight: 1
        $x_1_4 = "cmd /c ping 127.0.0.1" ascii //weight: 1
        $x_1_5 = "heroherohero" ascii //weight: 1
        $x_1_6 = "ransomware" ascii //weight: 1
        $x_1_7 = "killprocesses" ascii //weight: 1
        $x_1_8 = {2e 64 61 74 61 5f 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 61 74 61 5f 30 31}  //weight: 1, accuracy: Low
        $x_2_9 = {50 45 00 00 64 86 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 00 00 ?? ?? 00 00 ?? ?? 00 00 00 00 00 ?? ?? 5e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHN_2147914307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHN!MTB"
        threat_id = "2147914307"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RansomTuga.exe" wide //weight: 1
        $x_1_2 = "kernel32.dll" wide //weight: 1
        $x_1_3 = "file too large" ascii //weight: 1
        $x_1_4 = "connection reset" ascii //weight: 1
        $x_1_5 = "directory not empty" ascii //weight: 1
        $x_1_6 = "not a socket" ascii //weight: 1
        $x_1_7 = "GetTempPath2W" ascii //weight: 1
        $x_2_8 = {50 45 00 00 64 86 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e}  //weight: 2, accuracy: Low
        $x_2_9 = {e8 67 00 00 07 00 60 60 00 00 01 00 20 00 a8 94 00 00 08 00 80 80 00 00 01 00 20 00 28 08 01 00 09 00 00 00 00 00 01 00 20 00 28 20 04 00 0a 00}  //weight: 2, accuracy: High
        $x_2_10 = {4c 8b dc 48 83 ec 28 b8 04 00 00 00 4d 8d 4b 10 4d 8d 43 08 89 44 24 38 49 8d 53 18 89 44 24 40 49 8d 4b 08 e8 a3 fd ff ff 48 83 c4 28 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_FileCoder_CCJF_2147917358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.CCJF!MTB"
        threat_id = "2147917358"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 22 48 81 f9 ?? ?? ?? ?? 32 e3 48 81 f9 ?? ?? ?? ?? 80 f4 ?? 48 81 f9 ?? ?? ?? ?? 88 22 48 81 f9 ?? ?? ?? ?? 8a dc 48 81 f9 ?? ?? ?? ?? 48 ff c2 48 81 f9 ?? ?? ?? ?? 48 ff c1 48 81 f9 ?? ?? ?? ?? 48 81 f9 ?? ?? ?? ?? 72 ae}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_OKZ_2147921713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.OKZ!MTB"
        threat_id = "2147921713"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f b6 1c 13 45 31 d8 45 88 04 39 48 ff c7 4c 89 c8 4c 89 d2 66 90 48 39 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHX_2147921850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHX!MTB"
        threat_id = "2147921850"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 3
        $x_1_2 = "-----END PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "Go build ID:" ascii //weight: 1
        $x_1_4 = "s3.dualstack.us" ascii //weight: 1
        $x_1_5 = "bcryptprimitives" wide //weight: 1
        $x_1_6 = "RESTORE-MY-FILES.txt" ascii //weight: 1
        $x_1_7 = ".back" ascii //weight: 1
        $x_1_8 = ".pptx" ascii //weight: 1
        $x_2_9 = {50 45 00 00 64 86 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 8e 3e 00 00 b2 04 00 00 00 00 00 80 8a 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHX_2147921850_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHX!MTB"
        threat_id = "2147921850"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Select * from Win32_Process" wide //weight: 1
        $x_1_2 = "dllcache\\rndll32.exe" wide //weight: 1
        $x_1_3 = "\\Start Menu\\Programs\\Startup" wide //weight: 1
        $x_1_4 = "WhatsThisHelpID" wide //weight: 1
        $x_1_5 = "DisabledPicture" wide //weight: 1
        $x_3_6 = "conf64.dat" ascii //weight: 3
        $x_3_7 = ".Try2Cry" wide //weight: 3
        $x_1_8 = {2e 5a 72 64 61 74 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 62 73 73}  //weight: 1, accuracy: Low
        $x_2_9 = {50 45 00 00 64 86 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 00 00 b0 a1 00 00 f0 61 00 00 00 00 00 c4 80 5f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AYE_2147922975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AYE!MTB"
        threat_id = "2147922975"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "How to restore your files.txt" ascii //weight: 2
        $x_2_2 = "Your files have been encrypted due to unauthorized use of our item." ascii //weight: 2
        $x_1_3 = "To restore your files, you must buy a special program, this program belong to us alone." ascii //weight: 1
        $x_1_4 = "tongfake.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHAA_2147923193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHAA!MTB"
        threat_id = "2147923193"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HideSelection" wide //weight: 1
        $x_1_2 = "WhatsThisHelpID" wide //weight: 1
        $x_1_3 = "DisabledPicture" wide //weight: 1
        $x_3_4 = "Locked" wide //weight: 3
        $x_3_5 = "system32\\dllcache\\tskmgr.exe" wide //weight: 3
        $x_1_6 = {2e 5a 72 64 61 74 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 62 73 73}  //weight: 1, accuracy: Low
        $x_2_7 = {50 45 00 00 64 86 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 00 00 f8 a1 00 00 14 62 00 00 00 00 00 c4 a0 5f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_SO_2147923283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.SO!MTB"
        threat_id = "2147923283"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s.smert" ascii //weight: 2
        $x_2_2 = "%s\\README.txt" ascii //weight: 2
        $x_2_3 = "Your files have been fucked. There's no way back" ascii //weight: 2
        $x_2_4 = "What can you do about it" ascii //weight: 2
        $x_2_5 = "Start all over again" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHY_2147925244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHY!MTB"
        threat_id = "2147925244"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 3
        $x_1_2 = "-----END PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "Go build ID:" ascii //weight: 1
        $x_1_4 = "s3.dualstack.us" ascii //weight: 1
        $x_1_5 = "bcryptprimitives" wide //weight: 1
        $x_1_6 = "Server-Side-Encryption-Customer-Key" ascii //weight: 1
        $x_1_7 = ".back" ascii //weight: 1
        $x_1_8 = ".pptx" ascii //weight: 1
        $x_2_9 = {50 45 00 00 64 86 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 ?? 3e 00 00 b2 04 00 00 00 00 00 ?? ?? 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AYH_2147925312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AYH!MTB"
        threat_id = "2147925312"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "This program will encrypt your files and cannot be recovered. Are you sure you want to run it?" ascii //weight: 2
        $x_1_2 = "ENCODER ALL" ascii //weight: 1
        $x_1_3 = "Final warning, are you sure you want to run?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHZ_2147925473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHZ!MTB"
        threat_id = "2147925473"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 3
        $x_1_2 = "-----END PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "Go build ID:" ascii //weight: 1
        $x_1_4 = "s3.dualstack.us" ascii //weight: 1
        $x_1_5 = "bcryptprimitives" wide //weight: 1
        $x_1_6 = "vssadmin" ascii //weight: 1
        $x_1_7 = ".back" ascii //weight: 1
        $x_1_8 = ".pptx" ascii //weight: 1
        $x_2_9 = {50 45 00 00 64 86 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_MA_2147928077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.MA!MTB"
        threat_id = "2147928077"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 7b dd fc ff e8 36 d1 fd ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_MA_2147928077_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.MA!MTB"
        threat_id = "2147928077"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 0c 51 48 8b 95 c0 00 00 00 48 d1 e2 48 2b ca 48 8b 54 c5 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHAD_2147928181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHAD!MTB"
        threat_id = "2147928181"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 ?? 24 00 00 ?? 03 00 00 00 00 00 ?? ?? 06}  //weight: 2, accuracy: Low
        $x_3_2 = "HexaLocker" ascii //weight: 3
        $x_2_3 = "precisely from ZZART3XX" ascii //weight: 2
        $x_1_4 = "chacha20" ascii //weight: 1
        $x_1_5 = "your important files have been encrypted and the only way to recover them is to purchase the decryption key" ascii //weight: 1
        $x_1_6 = "follow these instructions and purchase the decryption key to recover your encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHAE_2147928458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHAE!MTB"
        threat_id = "2147928458"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 ?? 24 00 00 ?? 03 00 00 00 00 00 ?? ?? 06}  //weight: 2, accuracy: Low
        $x_3_2 = "encryptTicket" ascii //weight: 3
        $x_2_3 = "Your data has been stolen and encrypted" ascii //weight: 2
        $x_1_4 = ".backup.wallet.onepkg.config.tar" ascii //weight: 1
        $x_1_5 = "\\UNC" ascii //weight: 1
        $x_1_6 = "hangupkilled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHAF_2147928552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHAF!MTB"
        threat_id = "2147928552"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 64 86 0b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 02 2b 00 a2 39 00 00 b8 4f 00 00 1a 00 00 f0 13}  //weight: 2, accuracy: Low
        $x_3_2 = "Your files have been encrypted." ascii //weight: 3
        $x_2_3 = "To decrypt them, you must pay 1 Bitcoin to the following address:" ascii //weight: 2
        $x_1_4 = "smimeencrypt" ascii //weight: 1
        $x_1_5 = "extendedKeyUsage" ascii //weight: 1
        $x_1_6 = "Hardware Module Name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHAG_2147929147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHAG!MTB"
        threat_id = "2147929147"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 64 86 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 29 00 a6 00 00 00 78 7a 00 00 00 00 00 78 a6}  //weight: 2, accuracy: Low
        $x_3_2 = "All your files have been encrypted by CyberVolk ransomware" ascii //weight: 3
        $x_2_3 = "Please never try to recover your files without decryption key which I give you after pay" ascii //weight: 2
        $x_1_4 = "Are you sure this is right decription key" wide //weight: 1
        $x_1_5 = "Copy BTC" wide //weight: 1
        $x_1_6 = "Encrypting File" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AMCW_2147929151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AMCW!MTB"
        threat_id = "2147929151"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "And you just need run this software on each computer that encrypted and all affected files will be decrypted" ascii //weight: 5
        $x_2_2 = "We send you a simple software with private Key" ascii //weight: 2
        $x_2_3 = "Short video of how to Decrypt" ascii //weight: 2
        $x_3_4 = "What are the guarantees that I can decrypt my files after paying the ransom" ascii //weight: 3
        $x_3_5 = "This means that we can decrypt all your files after paying the ransom" ascii //weight: 3
        $x_2_6 = "NET STOP IISADMIN" ascii //weight: 2
        $x_2_7 = "net stop mysql" ascii //weight: 2
        $x_1_8 = "taskkill /F /IM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHAI_2147931726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHAI!MTB"
        threat_id = "2147931726"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 ?? 28 00 00 e4 03 00 00 00 00 00 40 42 07}  //weight: 2, accuracy: Low
        $x_3_2 = ".doc.odt.sql.mdb.xls.ods.ppt" ascii //weight: 3
        $x_1_3 = "cookieuser" ascii //weight: 1
        $x_1_4 = "ReadMe.txt" ascii //weight: 1
        $x_1_5 = "CBCEncrypter" ascii //weight: 1
        $x_2_6 = "HexaLockerV2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_RHAJ_2147931782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.RHAJ!MTB"
        threat_id = "2147931782"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 28 29 00 00 f4 03 00 00 00 00 00 60 41 07}  //weight: 2, accuracy: Low
        $x_3_2 = ".doc.odt.sql.mdb.xls.ods.ppt" ascii //weight: 3
        $x_1_3 = "cookieuser" ascii //weight: 1
        $x_1_4 = "ReadMe.txt" ascii //weight: 1
        $x_1_5 = "CBCEncrypter" ascii //weight: 1
        $x_2_6 = "hexalocker" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AYF_2147937395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AYF!MTB"
        threat_id = "2147937395"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Vrunner.pdb" ascii //weight: 2
        $x_1_2 = "Your computer has been destroyed by Vrunner" ascii //weight: 1
        $x_1_3 = "You can get the key by paying the ransom" ascii //weight: 1
        $x_1_4 = "I have no money, I restart now, at least the computer can still use it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_SP_2147940039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.SP!MTB"
        threat_id = "2147940039"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I am the walrus. I have taken the liberty of protecting the data on your machine by encrypting it all" ascii //weight: 1
        $x_1_2 = "C:\\flag.txt.tusk" ascii //weight: 1
        $x_1_3 = "C:\\DECRYPT_YOUR_FILES.txt" ascii //weight: 1
        $x_1_4 = "repos\\TuskLocker2\\x64\\Release\\TuskLocker2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AYG_2147942953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AYG!MTB"
        threat_id = "2147942953"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "This IS real ransomware. Are you sure you want to run it?" ascii //weight: 2
        $x_1_2 = "Do not close the window or it could lead to data loss!" ascii //weight: 1
        $x_1_3 = "encrypted_files.txt" ascii //weight: 1
        $x_1_4 = "aaa_TouchMeNot_.txt" ascii //weight: 1
        $x_1_5 = "Software\\Classes\\.xcrypt\\DefaultIcon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_TMX_2147945110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.TMX!MTB"
        threat_id = "2147945110"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 48 01 48 8b 45 f0 48 8b 55 10 89 4c 24 28 48 8b 4d 18 48 89 4c 24 20}  //weight: 5, accuracy: High
        $x_5_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_1_3 = "Cookies" ascii //weight: 1
        $x_1_4 = "MyClone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_FileCoder_GTD_2147947669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.GTD!MTB"
        threat_id = "2147947669"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "We have encrypted your data and exfiltrated sensitive documents" ascii //weight: 1
        $x_1_2 = "Screenshot of other customers who have paid and received decryption" ascii //weight: 1
        $x_1_3 = "To recover your files and prevent public disclosure of documents a payment in form of crypto currency is required" ascii //weight: 1
        $x_1_4 = "Vssadmindeleteshadows/all/quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_GXD_2147947793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.GXD!MTB"
        threat_id = "2147947793"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR IMPORTANT FILES ARE STOLEN AND ENCRYPTED" ascii //weight: 1
        $x_1_2 = "/c SCHTASKS.exe /Delete /TN \"Windows Update ALPHV\" /F" ascii //weight: 1
        $x_1_3 = "Contact us immediately to prevent data leakage and recover your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_KK_2147948345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.KK!MTB"
        threat_id = "2147948345"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {43 33 1c 87 45 89 e0 41 c1 ec 08 45 0f b6 e4 47 0f b6 24 23 4c 8d 3d ?? ?? ?? ?? 43 33 1c a7 45 0f b6 c0 47 0f b6 04 18 4c 8d 25 f5 38 1b 00 43 33 1c 84 eb}  //weight: 20, accuracy: Low
        $x_10_2 = {48 81 ec 98 00 00 00 48 89 ac 24 90 00 00 00 48 8d ac 24 90 00 00 00 48 89 84 24 a0 00 00 00 49 c7 c5 00 00 00 00 4c 89 ac 24 88 00 00 00 c6 44 24 3f 00 48 89 d9 48 8d 3d cf da 02 00 be 0b 00 00 00 48 89 c3 31 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_BA_2147952372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.BA!MTB"
        threat_id = "2147952372"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "file_xor_locker" ascii //weight: 1
        $x_1_2 = "decrypt" ascii //weight: 1
        $x_1_3 = "README.txt" ascii //weight: 1
        $x_1_4 = "Your files have been encrypted." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_BA_2147952372_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.BA!MTB"
        threat_id = "2147952372"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted_file.txt" ascii //weight: 1
        $x_1_2 = ".locked" ascii //weight: 1
        $x_1_3 = "ransom_note.txt" ascii //weight: 1
        $x_1_4 = "Your files have been encrypted." ascii //weight: 1
        $x_1_5 = "ransom.txt" ascii //weight: 1
        $x_1_6 = "To decrypt your files, send $100 to [email address]." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win64_FileCoder_KAB_2147953713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.KAB!MTB"
        threat_id = "2147953713"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 44 24 60 48 89 5c 24 58 44 0f 11 bc 24 98 00 00 00 44 0f 11 bc 24 a8 00 00 00 48 c7 84 24 a0 00 00 00 08 00 00 00 48 8d 0d}  //weight: 10, accuracy: High
        $x_8_2 = "Critical data has been exfiltrated." ascii //weight: 8
        $x_5_3 = "Files have been encrypted." ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_B_2147956780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.B!AMTB"
        threat_id = "2147956780"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wrong password! Files remain encrypted." ascii //weight: 1
        $x_1_2 = "Password correct! Decrypting files" ascii //weight: 1
        $x_1_3 = "encV.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_A_2147957164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.A!AMTB"
        threat_id = "2147957164"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" ascii //weight: 1
        $x_1_2 = "start /b cmd.exe /c start https://example.com/ransomware.exe" ascii //weight: 1
        $x_1_3 = "To decrypt them, send $100 to example@example.com" ascii //weight: 1
        $x_1_4 = "C:\\Desktop\\ransomnote.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_AR_2147958353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.AR!AMTB"
        threat_id = "2147958353"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted!" ascii //weight: 1
        $x_1_2 = "key.bin" ascii //weight: 1
        $x_1_3 = "ransom.txt" ascii //weight: 1
        $x_1_4 = "Encryption process completed." ascii //weight: 1
        $x_1_5 = "Ransomware started." ascii //weight: 1
        $x_1_6 = "Ransom note created." ascii //weight: 1
        $x_1_7 = "Ransomware finished." ascii //weight: 1
        $x_1_8 = "??0_Lockit@std@@QEAA@H@Z" ascii //weight: 1
        $x_1_9 = "??1_Lockit@std@@QEAA@XZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCoder_GP_2147958370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCoder.GP!AMTB"
        threat_id = "2147958370"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pay me $1000 within 72 hours or your files will be deleted forever." ascii //weight: 1
        $x_1_2 = "Contact me at [email address]." ascii //weight: 1
        $x_1_3 = "C:\\\\Program Files\\WebMoney\\" ascii //weight: 1
        $x_1_4 = "Send us 100000 bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


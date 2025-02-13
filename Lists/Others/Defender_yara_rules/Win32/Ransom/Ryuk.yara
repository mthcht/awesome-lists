rule Ransom_Win32_Ryuk_S_2147731377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.S!MTB"
        threat_id = "2147731377"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UNIQUE_ID_DO_NOT_REMOVE" wide //weight: 1
        $x_1_2 = "RyukReadMe.txt" wide //weight: 1
        $x_1_3 = "You will receive btc address for payment in the reply letter" ascii //weight: 1
        $x_1_4 = "No system is safe" ascii //weight: 1
        $x_1_5 = "crypted try to clean" ascii //weight: 1
        $x_1_6 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 8d 04 92 03 c0 2b c8 83 f9 09 7e ?? 83 c1 57 eb ?? 83 c1 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Ryuk_2147734607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk"
        threat_id = "2147734607"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RyukReadMe.txt" wide //weight: 1
        $x_1_2 = "rsa keys" wide //weight: 1
        $x_1_3 = "$Recycle.Bin" wide //weight: 1
        $x_1_4 = "cant check information, start DECRYPTOR with administrative privileges" ascii //weight: 1
        $x_1_5 = "write full address of file, example" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_2147734607_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk"
        threat_id = "2147734607"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net stop McAfeeDLPAgentService" wide //weight: 1
        $x_1_2 = "net stop samss" wide //weight: 1
        $x_1_3 = "taskkill /IM sqlwriter.exe" wide //weight: 1
        $x_1_4 = "wmiprvse -Embedding" wide //weight: 1
        $x_1_5 = "icacls \"C:\\*\" /grant Everyone:F /T /C /Q" wide //weight: 1
        $x_4_6 = "-e,--encrypt option needed" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ryuk_B_2147741518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.B"
        threat_id = "2147741518"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "RyukReadMe.html" wide //weight: 5
        $x_5_2 = ".RYK" wide //weight: 5
        $x_1_3 = "DECRYPT START FOR 30 SECONDS, TURN OFF ALL ANTIVIRUS SOFTWARE" ascii //weight: 1
        $x_1_4 = "C:\\mypath\\somepath\\somefile.xls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ryuk_AA_2147742729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.AA"
        threat_id = "2147742729"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RyukReadMe.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_C_2147747880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.C!MTB"
        threat_id = "2147747880"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 0b 00 00 75 33 00 8b 4d ?? 2b 4d ?? 89 4d ?? 8b 55 ?? c1 e2 04 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? 8b 55 ?? c1 ea 05 89 55 ?? 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_SB_2147749354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.SB!MSR"
        threat_id = "2147749354"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "operation_would_block" ascii //weight: 1
        $x_1_2 = "owner dead" ascii //weight: 1
        $x_1_3 = "MYCODE" ascii //weight: 1
        $x_1_4 = "Eurpeans crucifixion" ascii //weight: 1
        $x_1_5 = "DXBARDATECOMBO" wide //weight: 1
        $x_1_6 = "SP_SHADOW21" wide //weight: 1
        $x_1_7 = "FindFirstFileW" ascii //weight: 1
        $x_1_8 = "FindNextFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_BS_2147749793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.BS!MTB"
        threat_id = "2147749793"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 6a 23 33 d2 5b 8d 0c 06 8b c6 f7 f3 8b 44 24 ?? 8a 04 02 30 01 46 3b 74 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_DHA_2147750748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.DHA!MTB"
        threat_id = "2147750748"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c1 99 f7 7d 0c 8a 04 97 28 04 31 41 3b 4d 14 7c ee}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_AA_2147751390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.AA!MTB"
        threat_id = "2147751390"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8b 45 0c 8b 55 08 89 d1 09 c1 8b 45 0c 8b 55 08 21 d0 f7 d0 21 c8 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f0 8b 55 0c 01 d0 8a 00 0f be c0 89 44 24 04 8b 45 e8 89 04 24 e8 ?? ?? ff ff 88 03 ff 45 f0 8b 45 f0 3b 45 ec 0f 92 c0 84 c0 0f 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "CryptAcquireContextA" ascii //weight: 1
        $x_1_4 = "PIMAGE_TLS_CALLBACK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_A_2147751615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.A!!Ryuk.SD!MTB"
        threat_id = "2147751615"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "Ryuk: an internal category used to refer to some threats"
        info = "SD: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RyukReadMe.html" ascii //weight: 1
        $x_1_2 = ":\\Windows\\System32\\net.exe\" stop \"samss\"" ascii //weight: 1
        $x_1_3 = "lismovacol1981@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Ryuk_AS_2147751929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.AS!MTB"
        threat_id = "2147751929"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 22 00 a1 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05}  //weight: 1, accuracy: Low
        $x_1_2 = "JohnDoe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_DA_2147761953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.DA!MTB"
        threat_id = "2147761953"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your system is locked down" ascii //weight: 1
        $x_1_2 = "Do not try to decrypt" ascii //weight: 1
        $x_1_3 = "otherwise you will damage fails" ascii //weight: 1
        $x_1_4 = "For decryption tool write on the email" ascii //weight: 1
        $x_1_5 = "we will publish all private data on http://conti.news/TEST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Ryuk_ZB_2147763439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.ZB!MTB"
        threat_id = "2147763439"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Default User\\finish" ascii //weight: 1
        $x_1_2 = "firefoxconfig" ascii //weight: 1
        $x_3_3 = "UNIQUE_ID_DO_NOT_REMOVE" wide //weight: 3
        $x_3_4 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 8d 04 92 03 c0 2b c8 83 f9 09 7e ?? 83 c1 57 eb ?? 83 c1 30}  //weight: 3, accuracy: Low
        $x_1_5 = "tbirdconfig" wide //weight: 1
        $x_1_6 = "Ntrtscan" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ryuk_MZ_2147763690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.MZ!MTB"
        threat_id = "2147763690"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.torproject" wide //weight: 1
        $x_1_2 = "*HELP_YOUR_FILES*" ascii //weight: 1
        $x_1_3 = "CRYPTOWALL" wide //weight: 1
        $x_1_4 = "marketcryptopartners.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Ryuk_BY_2147764334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.BY!MTB"
        threat_id = "2147764334"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc stop windefend" ascii //weight: 1
        $x_1_2 = "run/v msascui/f reg delete" ascii //weight: 1
        $x_1_3 = "shutdown -s -t 7? -c &quot;A VIRUS IS TAKING OVER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Ryuk_PA_2147766766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.PA!MTB"
        threat_id = "2147766766"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 d2 f7 f7 8b 45 ?? 0f b6 04 08 02 c3 8b f2 8a 14 0e 88 04 0e 8b 45 ?? 02 d3 88 14 08 0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 f7 8b 7d ?? 47 89 7d ?? 03 55 ?? 0f b6 04 0a 8b 55 ?? 02 c3 32 44 3a ?? 83 6d 0c 01 88 47 ?? 75}  //weight: 3, accuracy: Low
        $x_1_2 = {5c 73 68 65 6c 6c 5c 6c 65 67 61 63 79 73 61 6d 70 6c 65 73 5c 61 70 70 62 61 72 5c [0-16] 5c 41 70 70 42 61 72 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "yuAAQERWEARDFGSFdgtgfgSZXAWQFAs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_SA_2147766770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.SA!MTB"
        threat_id = "2147766770"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "CSBhvSWCvFRvfCfAoJdoFuAUmK" ascii //weight: 2
        $x_1_2 = "Qkkbal" ascii //weight: 1
        $x_1_3 = {8d 76 00 8b 1c ?? 8b 2c ?? 81 e5 7f 7f 7f 7f 89 de 81 e6 7f 7f 7f 7f 01 ee 33 1c ?? 81 e3 80 80 80 80 31 de 89 ?? ?? 47 39 ?? ?? ?? 77}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 c0 0f b6 12 01 d0 31 d2 f7 f5 8a ?? ?? ?? 8b ?? ?? ?? 02 04 ?? 8b ?? ?? ?? 32 04 ?? 8b ?? ?? ?? 88 04 ?? 47 3b ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_2147767170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk!MTB"
        threat_id = "2147767170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$password = '" ascii //weight: 1
        $x_1_2 = "$torlink = '" ascii //weight: 1
        $x_1_3 = "rep.exe" wide //weight: 1
        $x_1_4 = "REP" wide //weight: 1
        $x_1_5 = "RYUKTM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_2147767170_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk!MTB"
        threat_id = "2147767170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$password = '" ascii //weight: 1
        $x_1_2 = "$torlink = '" ascii //weight: 1
        $x_1_3 = "RYUKTM" ascii //weight: 1
        $x_1_4 = "Ntdll.dll" ascii //weight: 1
        $x_1_5 = "NtQueryInformationProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_2147767170_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk!MTB"
        threat_id = "2147767170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 7d ?? 8b 45 ?? 99 f7 7d ?? 8b 45 ?? 8b 0c 90 89 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 45 ?? 60 33 c0 8a 45 ?? 33 c9 8b 4d ?? d2 c8 88 45 ?? 61 8b 4d ?? 03 4d ?? 8a 55 ?? 88 11 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_DB_2147767180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.DB!MTB"
        threat_id = "2147767180"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "RyukReadMe.html" ascii //weight: 1
        $x_1_3 = "DECRYPT_INFORMATION.html" ascii //weight: 1
        $x_1_4 = "@protonmail.com" ascii //weight: 1
        $x_1_5 = "del /s /f /q c:\\*.VHD c:\\*.bac c:\\*.bak c:\\*.wbcat c:\\*.bkf c:\\Backup*.* c:\\backup*.* c:\\*.set c:\\*.win c:\\*.dsk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Ryuk_A_2147768567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.A!MTB"
        threat_id = "2147768567"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c8 32 4d ?? [0-11] 88 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 45 ef 3b ?? 75 ?? [0-4] 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 ?? 8b 44 24 04 f7 e1 c2 ?? ?? 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2}  //weight: 1, accuracy: Low
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_BX_2147769574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.BX!MTB"
        threat_id = "2147769574"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RyukReadMe.txt" wide //weight: 1
        $x_1_2 = "pool.minexmr.com" ascii //weight: 1
        $x_1_3 = "HIT BY RANSOMWARE.txt" wide //weight: 1
        $x_1_4 = "\\system32\\KeyLogs.txt" wide //weight: 1
        $x_1_5 = "taskkill /f /im explo" wide //weight: 1
        $x_1_6 = "KISSES_TO_MCAFEE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Ryuk_PI_2147773658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.PI!MTB"
        threat_id = "2147773658"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 89 4d ?? 81 ?? ?? ?? ?? 00 00 0f [0-5] 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 89 45 ?? 8b 4d ?? 81 ?? a3 00 00 00 89 4d ?? 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? f7 d0 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 81 ?? a3 00 00 00 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 81 ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_B_2147779853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.B!!Ryuk.B"
        threat_id = "2147779853"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "Ryuk: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "RyukReadMe.html" wide //weight: 5
        $x_5_2 = ".RYK" wide //weight: 5
        $x_1_3 = "DECRYPT START FOR 30 SECONDS, TURN OFF ALL ANTIVIRUS SOFTWARE" ascii //weight: 1
        $x_1_4 = "C:\\mypath\\somepath\\somefile.xls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ryuk_ZZ_2147782814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.ZZ"
        threat_id = "2147782814"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {55 8b ec 83 ec ?? 53 (33 c9 56 57|56 57) [0-32] 99 f7 7d 0c 8b ?? ?? (89|8b) ?? ?? (89|8b) [0-10] 88 45 ff 60 33 c0 8a 45 ff 33 c9 8b 4d f4 d2 c8 88 45 ff 61 8b}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_ZU_2147783741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.ZU"
        threat_id = "2147783741"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 5a 7d 45 33 c9 8b 55 fc c1 e2 05 03 55 08 89 0a 89 4a 04 89 4a 08 89 4a 0c 89 4a 10 89 4a 14 89 4a 18 89 4a 1c 8b 45 fc c1 e0 05 8b 4d 08 8b 55 fc 89 54 01 18 8b 45 fc c1 e0 05 8b 4d 08 c7 44 01 1c 00 00 00 00 eb ac}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ryuk_XZ_2147805829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.XZ!!Ryuk.XZ"
        threat_id = "2147805829"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "Ryuk: an internal category used to refer to some threats"
        info = "XZ: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RyukReadMe.html" wide //weight: 10
        $x_1_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 45 00 6e 00 68 00 61 00 6e 00 63 00 65 00 64 00 20 00 52 00 53 00 41 00 20 00 61 00 6e 00 64 00 20 00 41 00 45 00 53 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 69 00 63 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "-----BEGIN PUBLIC KEY-" wide //weight: 1
        $x_1_4 = {2d 00 2d 00 2d 00 2d 00 2d 00 45 00 4e 00 44 00 20 00 50 00 55 00 42 00 4c 00 49 00 43 00 20 00 4b 00 45 00 59 00 2d 00 2d 00 2d 00 2d 00 2d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ryuk_MKV_2147901364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ryuk.MKV!MTB"
        threat_id = "2147901364"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 33 45 fc 25 ff 00 00 00 8b 4d fc c1 e9 08 33 8c 85 ?? ?? ?? ?? 89 4d fc 8b 55 08 83 c2 01 89 55 08 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "$password = '" ascii //weight: 1
        $x_1_3 = "$torlink = '" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


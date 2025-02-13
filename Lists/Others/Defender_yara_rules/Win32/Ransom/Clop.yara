rule Ransom_Win32_Clop_A_2147733496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.A!MTB"
        threat_id = "2147733496"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff ff 48 03 00 00 73 ?? 8b ?? ?? ff ff ff 8b ?? ?? ?? ?? ?? ?? 89 ?? ?? ff ff ff c7 85 ?? ?? ?? ?? 00 00 00 00 [0-6] 89 ?? ?? ff ff ff 8b ?? ?? ff ff ff 2b ?? ?? ff ff ff 89 ?? ?? ff ff ff 8b ?? ?? ff ff ff 83 ?? 50 89 ?? ?? ff ff ff c1 85 ?? ff ff ff 05 8b ?? ?? ff ff ff 33 ?? ?? ff ff ff 89 ?? ?? ff ff ff 8b ?? ?? ff ff ff 8b [0-5] 8b ?? ?? ff ff ff 89 ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_E_2147741619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.E"
        threat_id = "2147741619"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "you_offer.txt" ascii //weight: 1
        $x_1_2 = "/c del  \"%s\" >> NUL" ascii //weight: 1
        $x_1_3 = "%s\\resort0-0-0-1-1-0.bat" ascii //weight: 1
        $x_1_4 = "%s\\systempdisk_11_23_556_6.bat" ascii //weight: 1
        $x_1_5 = "%s\\clearnetworkdns_11-22-33.bat" ascii //weight: 1
        $x_1_6 = "%s\\clearsystems-10-1.bat" ascii //weight: 1
        $x_10_7 = "Clopfdwsj" ascii //weight: 10
        $x_10_8 = "ClopReadMe.txt" wide //weight: 10
        $x_10_9 = "Cl0pReadMe.txt" wide //weight: 10
        $x_10_10 = "%s%s.Clop" wide //weight: 10
        $x_10_11 = "%s%s.Cl0p" wide //weight: 10
        $x_10_12 = "CIopReadMe.txt" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Clop_GG_2147742096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.GG!MTB"
        threat_id = "2147742096"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\CIopReadMe.txt" ascii //weight: 1
        $x_1_2 = "/c del  \"%s\" >> NUL" ascii //weight: 1
        $x_1_3 = "VipreAAPSvc.exe" ascii //weight: 1
        $x_1_4 = {f7 e6 8b c6 c1 ea ?? 8b ca c1 e1 ?? 03 ca 03 c9 2b c1 8a 80 ?? ?? ?? ?? 30 04 1e 46 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_B_2147742344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.B"
        threat_id = "2147742344"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 56 8b 55 cc 8b 45 dc 8b 0c 90 89 4d 94 8b 15 ?? ?? ?? ?? 89 55 98 8b 45 94 2b 45 cc 89 45 94 8b 4d e4 83 e9 ?? 89 4d e4 8b 55 94 33 55 98 89 55 94 8b 45 e4 2d ?? ?? ?? ?? 89 45 e4 c1 45 94 07 8b 4d 94 33 4d 98 89 4d 94 8b 55 cc 8b 45 f8 8b 4d 94 89 0c 90 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_PA_2147748542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.PA!MTB"
        threat_id = "2147748542"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 c4 81 c2 67 55 ba 00 89 55 c4 8b [0-4] 8b [0-4] 8b 14 81 89 [0-5] 8b 45 c4 69 c0 00 c0 0f 00 89 45 c4 8b 0d 38 93 40 00 89 8d [0-4] 8b 55 c4 81 ea 00 f0 ff 00 89 55 c4 8b 85 [0-4] 33 85 [0-4] 89 85 [0-4] 8b 4d c4}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c1 00 a0 ba 0b 89 4d c4 c1 85 [0-4] 09 8b 55 c4 81 ea ab 5a 05 00 89 55 c4 8b 85 [0-4] 33 85 [0-4] 89 85 [0-4] 8b 4d c4 81 c1 ab 5a 15 00 89 4d c4 8b 95 [0-4] 2b 55 [0-2] 89 95 [0-4] 8b 45 c4 2d 00 f0 ff 0f 89 45 c4 8b 4d [0-2] 8b 55 [0-2] 8b 85 [0-4] 89 04 8a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_MR_2147750151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.MR!MTB"
        threat_id = "2147750151"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 14 81 e9 46 00 33 85 ?? ?? ?? ?? 89 85 [0-20] c1 85 [0-8] 8b 95 ?? ?? ?? ?? 33 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 8b 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_PB_2147750889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.PB!MTB"
        threat_id = "2147750889"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_2 = "READ_ME_!!!.TXT" wide //weight: 1
        $x_1_3 = ".C_L_O_P" wide //weight: 1
        $x_1_4 = "%s runrun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_PB_2147750889_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.PB!MTB"
        threat_id = "2147750889"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "&*^@QDSJGIO" ascii //weight: 10
        $x_10_2 = "&JTEH$WHD" ascii //weight: 10
        $x_1_3 = "/C netsh advfirewall set domainprofile state off" ascii //weight: 1
        $x_1_4 = "/C netsh advfirewall set  currentprofile state off" ascii //weight: 1
        $x_1_5 = "/C netsh advfirewall set privateprofile state off" ascii //weight: 1
        $x_1_6 = "/C netsh advfirewall set publicprofile state off" ascii //weight: 1
        $x_1_7 = "/C netsh advfirewall set  allprofiles state off" ascii //weight: 1
        $x_1_8 = "/C netsh firewall set opmode mode=DISABLE" ascii //weight: 1
        $x_1_9 = "&HDGF$W#GSRGHREGRW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Clop_PB_2147750889_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.PB!MTB"
        threat_id = "2147750889"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\CIopReadMe.txt" wide //weight: 1
        $x_1_2 = "srclient.dll" wide //weight: 1
        $x_1_3 = "RC_DATAMAKEMONEY" wide //weight: 1
        $x_1_4 = "SRRemoveRestorePoint" ascii //weight: 1
        $x_1_5 = "BestChangeT0pMoney^_-666" ascii //weight: 1
        $x_1_6 = "BestChangeT0p^_-666" ascii //weight: 1
        $x_10_7 = {ff 2f c6 85 ?? ?? ?? ff 63 c6 85 ?? ?? ?? ff 20 c6 85 ?? ?? ?? ff 76 c6 85 ?? ?? ?? ff 73 c6 85 ?? ?? ?? ff 73 c6 85 ?? ?? ?? ff 61 c6 85 ?? ?? ?? ff 64 c6 85 ?? ?? ?? ff 6d c6 85 ?? ?? ?? ff 69 c6 85 ?? ?? ?? ff 6e c6 85 ?? ?? ?? ff 2e c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 78 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 20 c6 85 ?? ?? ?? ff 44 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 6c c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 74 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 20 c6 85 ?? ?? ?? ff 53 c6 85 ?? ?? ?? ff 68 c6 85 ?? ?? ?? ff 61 c6 85 ?? ?? ?? ff 64 c6 85 ?? ?? ?? ff 6f c6 85 ?? ?? ?? ff 77 c6 85 ?? ?? ?? ff 73 c6 85 ?? ?? ?? ff 20 c6 85 ?? ?? ?? ff 2f c6 85 ?? ?? ?? ff 41 c6 85 ?? ?? ?? ff 6c c6 85 ?? ?? ?? ff 6c c6 85 ?? ?? ?? ff 20}  //weight: 10, accuracy: Low
        $x_10_8 = {0f b6 14 10 03 ca 81 e1 ff 00 00 00 8b 45 f8 0f b6 0c ?? 8b 55 08 03 55 ?? 0f b6 02 33 c1 8b 4d 08 03 4d ?? 88 01 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Clop_PC_2147750927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.PC!MTB"
        threat_id = "2147750927"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\CIopReadMe.txt" wide //weight: 1
        $x_1_2 = "srclient.dll" wide //weight: 1
        $x_1_3 = "RC_DATABIGBACK" wide //weight: 1
        $x_1_4 = "SRRemoveRestorePoint" ascii //weight: 1
        $x_1_5 = "MakeMoneyFromAir#777" ascii //weight: 1
        $x_10_6 = {b9 4f 00 00 00 66 89 4d ?? ba 43 00 00 00 66 89 55 ?? b8 58 00 00 00 66 89 45 ?? [0-128] b8 2e 00 00 00 66 89 85 ?? ?? ?? ?? b9 44 00 00 00 66 89 8d ?? ?? ?? ?? ba 4c 00 00 00 66 89 95 ?? ?? ?? ?? b8 4c 00 00 00 66 89 85 ?? ?? ?? ?? [0-128] b8 2e 00 00 00 66 89 45 ?? b9 43 00 00 00 66 89 4d ?? ba 49 00 00 00 66 89 55 ?? b8 4f 00 00 00 66 89 45 ?? b9 50 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_PE_2147765482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.PE!MTB"
        threat_id = "2147765482"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ".CIIp" wide //weight: 10
        $x_10_2 = ".CI0p" wide //weight: 10
        $x_1_3 = "BEGIN PUBLIC KEY" ascii //weight: 1
        $x_1_4 = "\\README_README.txt" wide //weight: 1
        $x_1_5 = "%s runrun" wide //weight: 1
        $x_1_6 = {2e 00 4f 00 c7 [0-6] 43 00 58 00 [0-26] c7 [0-6] 2e 00 63 00 c7 [0-6] 68 00 6d 00 [0-26] c7 [0-6] 2e 00 43 00 c7 [0-6] 49 00 30 00 66 89 [0-42] c7 [0-6] 2e 00 6d 00 c7 [0-6] 73 00 69 00 [0-26] c7 [0-6] 2e 00 44 00 c7 [0-6] 4c 00 4c 00 [0-26] c7 [0-6] 2e 00 45 00 c7 [0-6] 58 00 45 00 [0-26] c7 [0-6] 2e 00 69 00 c7 [0-6] 63 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Clop_SL_2147771149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.SL!MTB"
        threat_id = "2147771149"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s.Cllp" ascii //weight: 1
        $x_1_2 = "-runrun" ascii //weight: 1
        $x_1_3 = "temp.dat" ascii //weight: 1
        $x_1_4 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_5 = "/C vssadmin Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_6 = "%s\\README_README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_DX_2147771150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.DX!MTB"
        threat_id = "2147771150"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C vssadmin Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "/C net stop BackupExecVSSProvider /y" ascii //weight: 1
        $x_1_3 = "README_README.txt" ascii //weight: 1
        $x_1_4 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_DA_2147772038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.DA!MTB"
        threat_id = "2147772038"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CL0PREADME.txt" ascii //weight: 1
        $x_1_2 = ".Cl0p" ascii //weight: 1
        $x_1_3 = "res3.txt.CIop" ascii //weight: 1
        $x_1_4 = "README_README.txt" ascii //weight: 1
        $x_1_5 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Clop_ZA_2147774331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.ZA!MTB"
        threat_id = "2147774331"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\README_README.txt" wide //weight: 1
        $x_1_2 = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"" ascii //weight: 1
        $x_1_3 = "%s runrun" wide //weight: 1
        $x_1_4 = "%s%s.CIIp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_SIB_2147807749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.SIB!MTB"
        threat_id = "2147807749"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 20
        $x_20_2 = "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=" ascii //weight: 20
        $x_1_3 = "net stop \"Sophos Message Router\" /y" ascii //weight: 1
        $x_1_4 = "net stop \"Sophos MCS Client\" /y" ascii //weight: 1
        $x_1_5 = "net stop \"Sophos MCS Agent\" /y" ascii //weight: 1
        $x_1_6 = "net stop \"Sophos Device Control Service\" /y" ascii //weight: 1
        $x_1_7 = "net stop \"Sophos Clean Service\" /y" ascii //weight: 1
        $x_1_8 = "net stop \"Sophos Web Control Service\" /y" ascii //weight: 1
        $x_1_9 = "net stop \"Sophos System Protection Service\" /y" ascii //weight: 1
        $x_1_10 = "net stop \"Sophos Agent\" /y" ascii //weight: 1
        $x_1_11 = "net stop \"Sophos AutoUpdate Service\" /y" ascii //weight: 1
        $x_1_12 = "net stop \"Sophos File Scanner Service\" /y" ascii //weight: 1
        $x_1_13 = "net stop \"Sophos Safestore Service\" /y" ascii //weight: 1
        $x_1_14 = "net stop \"Sophos Health Service\" /y" ascii //weight: 1
        $x_1_15 = "net stop sophossps /y" ascii //weight: 1
        $x_1_16 = "net stop McShield /y" ascii //weight: 1
        $x_1_17 = "net stop Antivirus /y" ascii //weight: 1
        $x_1_18 = "net stop VeeamDeploymentService /y" ascii //weight: 1
        $x_1_19 = "net stop VeeamDeploySvc /y" ascii //weight: 1
        $x_1_20 = "net stop VeeamCatalogSvc /y" ascii //weight: 1
        $x_1_21 = "net stop VeeamBackupSvc /y" ascii //weight: 1
        $x_1_22 = "net stop VeeamRESTSvc /y" ascii //weight: 1
        $x_1_23 = "net stop VeeamCloudSvc /y" ascii //weight: 1
        $x_1_24 = "Veeam Backup Catalog Data Service" ascii //weight: 1
        $x_1_25 = "net stop VeeamMountSvc /y" ascii //weight: 1
        $x_1_26 = "net stop VeeamHvIntegrationSvc /y" ascii //weight: 1
        $x_1_27 = "net stop VeeamEnterpriseManagerSvc /y" ascii //weight: 1
        $x_1_28 = "net stop VeeamTransportSvc /y" ascii //weight: 1
        $x_1_29 = "net stop VeeamNFSSvc /y" ascii //weight: 1
        $x_1_30 = "net stop VeeamBrokerSvc /y" ascii //weight: 1
        $x_1_31 = "net stop BackupExecAgentAccelerator /y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 15 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Clop_PBE_2147844029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.PBE!MTB"
        threat_id = "2147844029"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "README_README.txt" wide //weight: 1
        $x_2_2 = "--BEGIN PUBLIC KEY--" ascii //weight: 2
        $x_1_3 = "runrun" wide //weight: 1
        $x_4_4 = {33 ca 0b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 0f bf 4d f0 03 c1 0f bf 55 f8 03 c2 0f bf 55 f0 8b 0d ?? ?? ?? ?? d3 fa 33 c2 0f be 0d ?? ?? ?? ?? 23 c8 88 0d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_H_2147846466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.H"
        threat_id = "2147846466"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!_READ_ME.RTF" wide //weight: 1
        $x_1_2 = ".C_I_0P" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_MA_2147846893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.MA!MTB"
        threat_id = "2147846893"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C net stop VeeamDeploymentService /y" ascii //weight: 1
        $x_1_2 = "/C net stop SstpSvc /y" ascii //weight: 1
        $x_1_3 = "/C net stop VeeamBackupSvc /y" ascii //weight: 1
        $x_1_4 = "/C vssadmin resize shadowstorage /for=" ascii //weight: 1
        $x_1_5 = "README_README.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_AA_2147848422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.AA!MTB"
        threat_id = "2147848422"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!!_READ_ME_!!!.TXT" wide //weight: 1
        $x_1_2 = ".C_I_0P" wide //weight: 1
        $x_1_3 = "%s\\Microsoft\\Outlook" wide //weight: 1
        $x_1_4 = "%s\\Microsoft\\Word" wide //weight: 1
        $x_1_5 = "%s\\Microsoft\\Office" wide //weight: 1
        $x_1_6 = "winsta0\\default" wide //weight: 1
        $x_1_7 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_8 = "-----END PUBLIC KEY-----" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_I_2147849111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.I"
        threat_id = "2147849111"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "temp.ocx" wide //weight: 1
        $x_1_2 = "ChangerWifi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Clop_LKV_2147899303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.LKV!MTB"
        threat_id = "2147899303"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ" ascii //weight: 10
        $x_1_2 = ".CIop" wide //weight: 1
        $x_1_3 = ".Cl0p" wide //weight: 1
        $x_1_4 = ".C_L_O_P" wide //weight: 1
        $x_1_5 = "runrun" wide //weight: 1
        $x_1_6 = "temp.ocx" wide //weight: 1
        $x_1_7 = "CIopReadMe.txt" wide //weight: 1
        $x_1_8 = "Cl0pReadMe.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Clop_AMCU_2147928447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Clop.AMCU!MTB"
        threat_id = "2147928447"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ".C_-_L_-_0_-_P" wide //weight: 5
        $x_3_2 = "WinSypTestChange" ascii //weight: 3
        $x_1_3 = "DEKJUBFSTXRYYHHJ" ascii //weight: 1
        $x_1_4 = "AAA_READ_AAA.TXT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


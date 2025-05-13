rule Trojan_Win32_KillMBR_AR_2147752363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.AR!MTB"
        threat_id = "2147752363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CustomMBR_Created_By_WobbyChip" ascii //weight: 10
        $x_4_2 = "Created By Angel Castillo. Your Computer Has Been Trashed." ascii //weight: 4
        $x_1_3 = ".\\PhysicalDrive" ascii //weight: 1
        $x_1_4 = "wininit.exe" ascii //weight: 1
        $x_1_5 = "services.exe" ascii //weight: 1
        $x_1_6 = "csrss.exe" ascii //weight: 1
        $x_4_7 = "All of your files have been encrypted" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KillMBR_MB_2147753493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.MB!MTB"
        threat_id = "2147753493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\PhysicalDrive0" ascii //weight: 1
        $x_1_2 = "schtasks.exe /Create /TN" ascii //weight: 1
        $x_1_3 = "\\EFI\\Microsoft\\Boot\\bootmgr.efi" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_MAK_2147787295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.MAK!MTB"
        threat_id = "2147787295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_2 = "NO ESCAPE" ascii //weight: 1
        $x_1_3 = "do not try to kill the process" ascii //weight: 1
        $x_1_4 = "Payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_MAK_2147787295_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.MAK!MTB"
        threat_id = "2147787295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lot of destructive potential" ascii //weight: 1
        $x_1_2 = "You will lose all of your data if you continue" ascii //weight: 1
        $x_1_3 = "trojan" ascii //weight: 1
        $x_1_4 = "final chance to stop this program" ascii //weight: 1
        $x_1_5 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_6 = "failed to open handle to physical drive" ascii //weight: 1
        $x_1_7 = "failed to overwrite boot data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_KillMBR_RPN_2147819351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.RPN!MTB"
        threat_id = "2147819351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EVILTEST" wide //weight: 1
        $x_1_2 = "\\\\.\\Harddisk0Partition1" wide //weight: 1
        $x_1_3 = "\\\\.\\PhysicalDrive0" wide //weight: 1
        $x_1_4 = "\\\\.\\Harddisk1Partition1" wide //weight: 1
        $x_1_5 = "\\\\.\\Harddisk2Partition1" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "Heya u are screwed XD" ascii //weight: 1
        $x_1_8 = "ShellExecuteA" ascii //weight: 1
        $x_1_9 = "WriteFile" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
        $x_1_11 = "InitializeCriticalSection" ascii //weight: 1
        $x_1_12 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_BD_2147822256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.BD!MTB"
        threat_id = "2147822256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MBR was successfuly erased" ascii //weight: 2
        $x_2_2 = "MineHack" ascii //weight: 2
        $x_2_3 = "Users\\Morsik" ascii //weight: 2
        $x_2_4 = "Something has gone wrong!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_BM_2147823576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.BM!MTB"
        threat_id = "2147823576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StarlightGlimmer_Virus" ascii //weight: 1
        $x_1_2 = "v1.0 MBRKiller new" ascii //weight: 1
        $x_1_3 = "BabukRansomwareSourceCode" ascii //weight: 1
        $x_1_4 = "MBRLock-master" ascii //weight: 1
        $x_1_5 = "KillMbr.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_BN_2147823577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.BN!MTB"
        threat_id = "2147823577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open Drive0 Failed!" ascii //weight: 1
        $x_1_2 = "read mbr Failed!" ascii //weight: 1
        $x_1_3 = "Already infected!" ascii //weight: 1
        $x_1_4 = "write backup mbr Failed!" ascii //weight: 1
        $x_1_5 = "Write originale mbr!" ascii //weight: 1
        $x_1_6 = "Write MBR OK!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_AC_2147833231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.AC!MTB"
        threat_id = "2147833231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WriteFile" ascii //weight: 1
        $x_1_2 = "CreateFileW" ascii //weight: 1
        $x_1_3 = "CloseHandle" ascii //weight: 1
        $x_2_4 = "\\.\\PhysicalDrive0" wide //weight: 2
        $x_2_5 = "Successfully obliterated ya mum" ascii //weight: 2
        $x_2_6 = "Ya mum too strong mate" ascii //weight: 2
        $x_2_7 = "\\Release\\Overwrite.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_AK_2147833244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.AK!MTB"
        threat_id = "2147833244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Coran2- Malware Alert" ascii //weight: 1
        $x_1_2 = "dangerous, it can delete ci.dll and etc, also it can overwrite your MBR that will make your computer unusable" ascii //weight: 1
        $x_1_3 = "want to run this? This is super dangerous as fuck, so if you want to kee" ascii //weight: 1
        $x_1_4 = "If you want to keep your computer safe from these destruction created by this malware just pres [No] to exit" ascii //weight: 1
        $x_1_5 = "Last Warning- You pressed [Yes] to the first warning, but why did you" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ARA_2147837287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ARA!MTB"
        threat_id = "2147837287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c1 99 f7 fe 8a f8 8b c1 99 8a df f7 ff 8b 45 ec fe cb 02 55 e4 41 32 d3 0a d7 8b 5d e0 88 10 83 c0 04 89 45 ec 3b cb 7c d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ARA_2147837287_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ARA!MTB"
        threat_id = "2147837287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 10 68 00 21 40 00 ff 15 ?? ?? ?? ?? 6a 00 8b f0 8d 45 f8 50 68 00 02 00 00 68 28 21 40 00 56 ff 15 ?? ?? ?? ?? 56 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = "\\\\.\\PhysicalDrive0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ARA_2147837287_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ARA!MTB"
        threat_id = "2147837287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "I think mbr will die" ascii //weight: 2
        $x_2_2 = "This is a virus!" ascii //weight: 2
        $x_2_3 = "DisableTaskMgr" ascii //weight: 2
        $x_2_4 = "DisableCMD" ascii //weight: 2
        $x_2_5 = "\\\\.\\PhysicalDrive0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ARA_2147837287_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ARA!MTB"
        threat_id = "2147837287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bootloader: Succesfully loaded" ascii //weight: 2
        $x_2_2 = "Memory region: 0x8000 has been loaded.\",13,10,13,10," ascii //weight: 2
        $x_2_3 = "Reset disk system" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ARA_2147837287_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ARA!MTB"
        threat_id = "2147837287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@reg delete \"HKEY_CLASSES_ROOT\" /f" ascii //weight: 2
        $x_2_2 = "@reg delete \"HKEY_CURRENT_USER\" /f" ascii //weight: 2
        $x_2_3 = "@reg delete \"HKEY_LOCAL_MACHINE\" /f" ascii //weight: 2
        $x_2_4 = "@reg delete \"HKEY_USERS\" /f" ascii //weight: 2
        $x_2_5 = "@reg delete \"HKEY_CURRENT_CONFIG\" /f" ascii //weight: 2
        $x_2_6 = "\\\\.\\PhysicalDrive0" ascii //weight: 2
        $x_2_7 = "\\\\.\\Harddisk0Partition" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_PAAF_2147850037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.PAAF!MTB"
        threat_id = "2147850037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG ADD hkcu\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system /v DisableTaskMgr /t reg_dword /d 1 /f" ascii //weight: 1
        $x_1_2 = "R.I.P PC" ascii //weight: 1
        $x_1_3 = "\\\\.\\PhysicalDrive0" wide //weight: 1
        $x_1_4 = "fakeerrorgetf*cked.exe" wide //weight: 1
        $x_1_5 = "Error: File corrupted! This program has been manipulated and maybe it's infected by a Virus or cracked." wide //weight: 1
        $x_1_6 = "THERE IS NO MERCY, so Bye Bye Windows!" wide //weight: 1
        $x_1_7 = "Run Malware?" wide //weight: 1
        $x_1_8 = "Are you sure? It will overwrite the MBR, continue?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_AD_2147851381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.AD!MTB"
        threat_id = "2147851381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 68 1c 00 09 00 56 ff d7 56 ff 15 ?? 20 00 10 68 d0 07 00 00 ff 15 ?? 20 00 10 ff 15 ?? 20 00 10 3d}  //weight: 2, accuracy: Low
        $x_2_2 = "\\.\\PHYSICALDRIVE0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ASAE_2147888716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ASAE!MTB"
        threat_id = "2147888716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 06 6a 00 6a 00 6a 00 68 ?? ?? 00 c0 ff d3 6a ff ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "REG ADD hkcu\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system /v DisableTaskMgr /t reg_dword /d 1 /f" ascii //weight: 1
        $x_1_3 = "The software you just executed is considered malware" wide //weight: 1
        $x_1_4 = "This malware will harm your computer and makes it unusable" wide //weight: 1
        $x_1_5 = "This is the last warning! The creator is not responsible for any damage made using this malware! Still execute it?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ASAF_2147888918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ASAF!MTB"
        threat_id = "2147888918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This is a malicious program that will cause your computer to malfunction" wide //weight: 1
        $x_1_2 = "You are solely responsible for any consequences caused by this malicious program" wide //weight: 1
        $x_1_3 = "This is the final reminder" wide //weight: 1
        $x_1_4 = "PHYSICALDRIVE0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_MA_2147894694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.MA!MTB"
        threat_id = "2147894694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "yangrouchuan999@163.com" ascii //weight: 2
        $x_2_2 = "Your computer has been trashed by the CRTYYtrojan" ascii //weight: 2
        $x_2_3 = "Nyan Cat..." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_AE_2147895129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.AE!MTB"
        threat_id = "2147895129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 89 e5 83 ec 38 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 03 00 00 00 c7 44 24 04 00 00 00 10 c7 04 24 00 40 40 00 a1 ?? 61 40 00 ff d0 83 ec 1c 89 45 f4 c7 44 24 10 00 00 00 00 8d 45 f0 89 44 24 0c c7 44 24 08 00 02 00 00 c7 44 24 04 40 40 40 00 8b 45 f4 89 04 24 a1 5c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_GPA_2147895467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.GPA!MTB"
        threat_id = "2147895467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15 34 10 40}  //weight: 2, accuracy: High
        $x_2_2 = "SarcomAI L3.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EM_2147896086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EM!MTB"
        threat_id = "2147896086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 54 24 28 83 c4 04 83 fa 08 72 33 8b 4c 24 10 8d 14 55 02 00 00 00 8b c1 81 fa 00 10 00 00 72 14 8b 49 fc 83 c2 23 2b c1 83 c0 fc 83 f8 1f 0f 87 c0}  //weight: 10, accuracy: High
        $x_2_2 = "start erasing logical drive" ascii //weight: 2
        $x_2_3 = "start erasing system physical drive" ascii //weight: 2
        $x_2_4 = "C:\\ProgramData\\log.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_RDB_2147903900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.RDB!MTB"
        threat_id = "2147903900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You executed the dangerous malware named nougar that can corrupt your system" wide //weight: 1
        $x_1_2 = "WARNING CORRUPTION HELL INCOMING!!!" wide //weight: 1
        $x_1_3 = "IT HURTS REALLY YOUR REAL PC!!!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_RDC_2147904044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.RDC!MTB"
        threat_id = "2147904044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 8b f0 8d 45 fc 50 68 00 80 00 00 68 ?? ?? ?? ?? 56 ff d3 56}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_CCHT_2147904393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.CCHT!MTB"
        threat_id = "2147904393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 10 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f0 6a 00 8d 45 fc 50 68 00 28 00 00 68 ?? ?? ?? ?? 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_AKM_2147905249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.AKM!MTB"
        threat_id = "2147905249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 ca 9a 3b 8b c7 8b bc 24 ?? ?? ?? ?? f7 e1 ba 00 ca 9a 3b 8b c8 8b 44 24 ?? f7 e2 03 ca 03 f0 8b 84 24 ?? ?? ?? ?? 13 c1 89 b4 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_NM_2147917175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.NM!MTB"
        threat_id = "2147917175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "zirconium the virus wants your pc" wide //weight: 2
        $x_2_2 = "You have to run a malware named Zirconium.exe" wide //weight: 2
        $x_2_3 = "free life hacks no fake!!11" wide //weight: 2
        $x_1_4 = "if you dont want to destroy your pc PRESS NO AND DELETE IT FASTLY!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EA_2147927334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EA!MTB"
        threat_id = "2147927334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DisableRegistryTools" wide //weight: 3
        $x_3_2 = "DisableCMD" wide //weight: 3
        $x_2_3 = "taskkill /f /im taskmgr.exe" ascii //weight: 2
        $x_3_4 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableChangePassword /t REG_DWORD /d 1 /f" ascii //weight: 3
        $x_3_5 = "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v HideFastUserSwitching /t REG_DWORD /d 1 /f" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ARAZ_2147928457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ARAZ!MTB"
        threat_id = "2147928457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\APM 08279+5255.pdb" ascii //weight: 2
        $x_2_2 = "overwrite the boot record" ascii //weight: 2
        $x_2_3 = "Malware, Run" ascii //weight: 2
        $x_2_4 = "\\\\.\\PhysicalDrive0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_ARAZ_2147928457_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.ARAZ!MTB"
        threat_id = "2147928457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your system has been destoryed!" ascii //weight: 2
        $x_2_2 = "\\WindowSmasher.pdb" ascii //weight: 2
        $x_2_3 = "\\\\.\\PhysicalDrive0" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_PAGD_2147931024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.PAGD!MTB"
        threat_id = "2147931024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\.\\PhysicalDrive" ascii //weight: 2
        $x_1_2 = "SeShutdownPrivilege" ascii //weight: 1
        $x_2_3 = "CustomMBR" ascii //weight: 2
        $x_1_4 = "-bypasswarning" ascii //weight: 1
        $x_2_5 = "If you run this app your computer will be destroyed" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EAIJ_2147934441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EAIJ!MTB"
        threat_id = "2147934441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b d0 c1 ea 0b 80 e2 06 32 d0 8a ca c0 e2 02 02 ca 02 c9 88 8c 05 f8 f3 fa ff 40 3d fe 0b 05 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EANI_2147936243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EANI!MTB"
        threat_id = "2147936243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 ea 04 0a 95 ?? ?? ?? ?? 32 da 8b 95 ?? ?? ?? ?? 88 9c 15 ?? ?? ?? ?? 42 89 95 ?? ?? ?? ?? 81 fa 10 09 05 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EANH_2147938600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EANH!MTB"
        threat_id = "2147938600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f be d2 0f af d1 88 94 05 f8 59 f1 ff 40 3d 00 a6 0e 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EAUQ_2147939537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EAUQ!MTB"
        threat_id = "2147939537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a c3 c0 e0 05 0a d0 88 94 1d ?? ?? ?? ?? 43 81 fb 80 a9 03 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EABR_2147940168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EABR!MTB"
        threat_id = "2147940168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ca 88 8c 05 78 56 fc ff 40 3d 80 a9 03 00 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EAN_2147941308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EAN!MTB"
        threat_id = "2147941308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be d2 0f af d1 88 94 05 ?? ?? ?? ?? 40 3d 00 53 07 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EIV_2147941309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EIV!MTB"
        threat_id = "2147941309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f6 24 80 88 84 0d ?? ?? ?? ?? 41 81 f9 80 a9 03 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillMBR_EYB_2147941311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillMBR.EYB!MTB"
        threat_id = "2147941311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a d0 88 94 1d ?? ?? ?? ?? 43 81 fb 80 a9 03 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


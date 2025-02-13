rule HackTool_Win32_AutoKMS_2147685180_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS"
        threat_id = "2147685180"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /run /i /tn \"WIN_KMS_key\" >nul " wide //weight: 1
        $x_1_2 = {74 73 5f 6b 6d 73 61 6c 6c 07 43 61 70 74 69 6f 6e 14 09 00 00 00 4b 4d 53 e6 bf 80 e6 b4 bb 0a 49 6d 61 67 65 49 6e 64 65 78 02 0d 06 4f 6e 53 68 6f 77 07 0d 74 73 5f 6b 6d 73 61 6c 6c 53 68}  //weight: 1, accuracy: High
        $x_1_3 = {5c 6b 00 6d 00 73 00 20 00 76 00 6c 00 20 00 61 00 6c 00 6c 00 c0 6f 3b 6d e5 5d 77 51 c6 96 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Win32_AutoKMS_2147685180_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS"
        threat_id = "2147685180"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oem-drv86.pdb" ascii //weight: 1
        $x_1_2 = "SystemRoot\\system32\\DRIVERS\\oem-drv86.sys" ascii //weight: 1
        $x_1_3 = "secr9tos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_AutoKMS_2147685180_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS"
        threat_id = "2147685180"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ratiborus" ascii //weight: 2
        $x_1_2 = "I do not want" ascii //weight: 1
        $x_1_3 = "Donate" ascii //weight: 1
        $x_1_4 = "http://forum.ru-board.com" ascii //weight: 1
        $x_1_5 = "https://money.yandex.ru" ascii //weight: 1
        $x_1_6 = "kms789.com" ascii //weight: 1
        $x_1_7 = "kms.03k.org" ascii //weight: 1
        $x_1_8 = "kms.digiboy.ir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_AutoKMS_2147685180_3
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS"
        threat_id = "2147685180"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /t /f /IM KMS8Load.exe >nul 2>&1" ascii //weight: 1
        $x_1_2 = "SppExtComObjHook.dll" ascii //weight: 1
        $x_1_3 = "Activate Windows and Office Permanently" ascii //weight: 1
        $x_1_4 = "%05u-%05u-%03u-%06u-03-%u-%04u.0000-%03d%04d" ascii //weight: 1
        $x_1_5 = "KMS_Emulation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_Win32_AutoKMS_2147685180_4
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS"
        threat_id = "2147685180"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "verify /v /ph /sha1 648384a4dee53d4c1c87e10d67cc99307ccc9c98" ascii //weight: 1
        $x_1_2 = "DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_3 = "W10 Digital Activation Program" ascii //weight: 1
        $x_1_4 = "Disable Defender" ascii //weight: 1
        $x_1_5 = "/delete /TN KMSTools /" ascii //weight: 1
        $x_1_6 = "Program Files\\Windows Defender\\MsMpEng.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Win32_AutoKMS_2147685180_5
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS"
        threat_id = "2147685180"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 4b 4d 53 20 53 65 72 76 65 72 2e 70 64 62 00}  //weight: 2, accuracy: High
        $x_1_2 = {28 4b 4d 53 20 56 35 29 20 73 65 6e 74 2e 0a 00 28 29 24 5e 2e 2a 2b 3f 5b 5d 7c 5c 2d 7b 7d 2c 3a 3d 21 0a 0d 08 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 65 66 61 75 6c 74 4b 4d 53 50 49 44 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 61 6e 64 6f 6d 4b 4d 53 50 49 44 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 4b 69 6c 6c 50 72 6f 63 65 73 73 4f 6e 50 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 35 35 30 34 31 2d 30 30 31 36 38 2d 33 30 35 2d 32 34 36 32 30 39 2d 30 33 2d 31 30 33 33 2d 37 36 30 30 2e 30 30 30 30 2d 30 35 32 32 30 31 30 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 52 70 63 53 65 72 76 65 72 55 73 65 50 72 6f 74 73 65 71 45 70 20 66 61 69 6c 65 64 20 77 69 74 68 20 63 6f 64 65 20 25 69 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 52 70 63 53 65 72 76 65 72 52 65 67 69 73 74 65 72 49 66 45 78 20 66 61 69 6c 65 64 20 77 69 74 68 20 63 6f 64 65 20 25 69 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 52 70 63 53 65 72 76 65 72 4c 69 73 74 65 6e 20 66 61 69 6c 65 64 20 77 69 74 68 20 63 6f 64 65 20 25 69 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 4b 4d 53 20 53 65 72 76 65 72 20 45 6d 75 6c 61 74 6f 72 20 72 75 6e 6e 69 6e 67 2e 2e 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 5e 28 5b 30 2d 39 5d 7b 35 7d 29 2d 28 5b 30 2d 39 5d 7b 35 7d 29 2d 28 5b 30 2d 39 5d 7b 33 7d 29 2d 28 5b 30 2d 39 5d 7b 36 7d 29 2d 28 5b 30 2d 39 5d 7b 32 7d 29 2d 28 5b 30 2d 39 5d 7b 34 7d 29 2d 28 5b 30 2d 39 5d 7b 34 7d 29 2e 28 5b 30 2d 39 5d 7b 34 7d 29 2d 28 5b 30 2d 39 5d 7b 37 7d 29 24 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 69 00 6f 00 6e 00 20 00 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 20 00 28 00 4b 00 4d 00 53 00 20 00 56 00 [0-4] 29 00 20 00 73 00 65 00 6e 00 74 00 2e 00 0a 00}  //weight: 1, accuracy: Low
        $x_1_13 = {00 41 63 74 69 76 61 74 69 6f 6e 20 72 65 73 70 6f 6e 73 65 20 28 4b 4d 53 20 56 [0-4] 29 20 73 65 6e 74 2e 0a 00}  //weight: 1, accuracy: Low
        $x_2_14 = {46 00 4f 00 52 00 20 00 2f 00 46 00 20 00 22 00 74 00 6f 00 6b 00 65 00 6e 00 73 00 3d 00 [0-4] 20 00 64 00 65 00 6c 00 69 00 6d 00 73 00 3d 00 20 00 22 00 20 00 25 00 50 00 20 00 49 00 4e 00 20 00 28 00 27 00 6e 00 65 00 74 00 73 00 74 00 61 00 74 00 20 00 2d 00 61 00 6e 00 6f 00 20 00 5e 00 7c 00 20 00 66 00 69 00 6e 00 64 00 73 00 74 00 72 00 20 00 3a 00 31 00 36 00 38 00 38 00 20 00 27 00 29 00 20 00 44 00 4f 00 20 00 65 00 63 00 68 00 6f 00 20 00 25 00 50 00}  //weight: 2, accuracy: Low
        $x_2_15 = {46 4f 52 20 2f 46 20 22 74 6f 6b 65 6e 73 3d [0-4] 20 64 65 6c 69 6d 73 3d 20 22 20 25 50 20 49 4e 20 28 27 6e 65 74 73 74 61 74 20 2d 61 6e 6f 20 5e 7c 20 66 69 6e 64 73 74 72 20 3a 31 36 38 38 20 27 29 20 44 4f 20 65 63 68 6f 20 25 50}  //weight: 2, accuracy: Low
        $x_2_16 = {00 35 35 30 34 31 2d 30 30 31 36 38 2d 33 30 35 2d 58 58 58 58 58 58 2d 30 33 2d 31 30 33 33 2d 56 56 56 56 2e 30 30 30 30 2d 44 44 44 59 59 59 59 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_AutoKMS_B_2147730148_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS.B"
        threat_id = "2147730148"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KMSInject.dll" wide //weight: 1
        $x_1_2 = "mephistooo2 - TNCTR.com" wide //weight: 1
        $x_1_3 = "Sanal KMS Sunucu" wide //weight: 1
        $x_1_4 = "SppExtComObjPatcher-kms\\Debug\\x64\\KMS.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_AutoKMS_C_2147731000_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS.C"
        threat_id = "2147731000"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Setup=KMSpico-setup.exe" ascii //weight: 10
        $x_1_2 = "Setup=kmsh.exe" ascii //weight: 1
        $x_1_3 = "Setup=dllservsys.exe" ascii //weight: 1
        $x_1_4 = "Setup=kmsb.exe" ascii //weight: 1
        $x_1_5 = "Setup=kmspicoh.exe" ascii //weight: 1
        $x_1_6 = "Setup=kmsdlli.exe" ascii //weight: 1
        $x_1_7 = "Setup=kmspicov.exe" ascii //weight: 1
        $x_10_8 = {46 75 6c 6c 43 72 61 63 6b 2e 76 6e 5f 4b 4d 53 70 69 63 6f 5f 31 30 2e ?? ?? ?? 5f 73 65 74 75 70 2e 72 61 72}  //weight: 10, accuracy: Low
        $x_1_9 = "Password : fullcrack.vn" ascii //weight: 1
        $x_10_10 = {40 24 26 25 ?? ?? 5c 4b 4d 53 70 69 63 6f 2d 73 65 74 75 70 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_11 = {40 24 26 25 ?? ?? 5c 6b 6d 73 64 6c 6c 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_AutoKMS_D_2147731321_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS.D"
        threat_id = "2147731321"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "185.125.230.210/KMSpico-setup.exe" ascii //weight: 1
        $x_1_2 = "Setup=KMSpico-setup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Win32_AutoKMS_D_2147731321_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS.D"
        threat_id = "2147731321"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Visual Studio\\SppExtComObjHook\\SppExtComObjHook\\bin\\x64\\Release\\SppExtComObjHook.pdb" ascii //weight: 1
        $x_1_2 = "InitHook@@YAXXZ" ascii //weight: 1
        $x_1_3 = "[SppExtComObj Hook B] Hooking Success" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_AutoKMS_SA_2147741757_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS.SA!MSR"
        threat_id = "2147741757"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Office 2013 Professional Plus" wide //weight: 1
        $x_1_2 = "Outlook 2013" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform" wide //weight: 1
        $x_1_4 = "Starting KMSEmulator service (ServiceName: %s)..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_AutoKMS_E_2147743252_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS.E!MSR"
        threat_id = "2147743252"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KMS Keygen" ascii //weight: 1
        $x_1_2 = "KMS activators" ascii //weight: 1
        $x_1_3 = "Office 2010 Toolkit.pdb" ascii //weight: 1
        $x_1_4 = "KMSEmulator.exe" wide //weight: 1
        $x_1_5 = "InstallAutoKMS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Win32_AutoKMS_NK_2147744620_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS.NK!MTB"
        threat_id = "2147744620"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KMSServerService" wide //weight: 1
        $x_1_2 = "Activation Request V4 send" wide //weight: 1
        $x_1_3 = "Activation Request V5 send" wide //weight: 1
        $x_1_4 = "RenewalInterval" wide //weight: 1
        $x_1_5 = "KmsRequests" wide //weight: 1
        $x_1_6 = "@KMSServerService" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_AutoKMS_HNB_2147929004_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AutoKMS.HNB!MTB"
        threat_id = "2147929004"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoKMS"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 43 00 00 00 6b 00 6d 00 73 00 2e 00 6a 00 6d 00 33 00 33 00 2e 00 6d 00 65 00 3a 00 31 00 36 00 38 00 38 00 00 00 4f 00 66 00 66 00 69 00 63 00 65 00 20 00 32 00 30 00 32 00 31 00 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 2f 00 44 00 20 00 2f 00 63 00 20 00 00 00 21 00 00 00 6b 00 6d 00 73 00 2e 00 6d 00 6f 00 65 00 79 00 75 00 75 00 6b 00 6f 00 2e 00 74 00 6f 00 70 00 3a 00 31 00 36 00 38 00 38 00 00 00 4f 00 66 00 66 00 69 00 63 00}  //weight: 1, accuracy: High
        $x_2_3 = {00 00 6b 00 6d 00 73 00 38 00 2e 00 4d 00 53 00 47 00 75 00 69 00 64 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 3a 00 31 00 36 00 38 00 38 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


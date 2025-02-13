rule TrojanDownloader_MSIL_Tiny_AEE_2147742460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.AEE!MTB"
        threat_id = "2147742460"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1a 00 00 00 07 00 00 00 05 00 00 00 11 00 00 00 03 00 00 00 24 00 00 00 2a 00 00 00 0c 00 00 00 02 00 00 00 05 00 00 00 05 00 00 00 08 00 00 00 01 00 00 00 03 00 00 00 02 00 00 00 03 00 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_PA_2147754592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.PA!MTB"
        threat_id = "2147754592"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 1e 00 00 0a 25 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6f 16 00 00 0a 6f 17 00 00 0a 72 ?? 00 00 70 28 ?? ?? ?? ?? 6f 20 00 00 0a [0-2] 25 17 6f 21 00 00 0a [0-2] 25 17 6f 22 00 00 0a [0-2] 25 72 ?? 00 00 70 6f 23 00 00 0a [0-16] de 11}  //weight: 1, accuracy: Low
        $x_1_2 = "/C choice /C Y /N /D Y /T 1 & Del" wide //weight: 1
        $x_1_3 = {5c 4c 69 6d 65 2d 44 72 6f 70 70 65 72 5c 4c 69 6d 65 2d 44 72 6f 70 70 65 72 2d 31 5c [0-32] 5c 4c 69 6d 65 2d 44 72 6f 70 70 65 72 2d 31 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = "Lime-Dropper-1.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_PB_2147755591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.PB!MTB"
        threat_id = "2147755591"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 06 00 00 0a 72 01 00 00 70 28 07 00 00 0a 18 73 08 00 00 0a 0a 00 72 ?? 00 00 70 28 09 00 00 0a 28 02 00 00 06 0b 06 07 16 07 8e 69 6f ?? 00 00 0a 00 00 de}  //weight: 1, accuracy: Low
        $x_1_2 = {28 06 00 00 0a 72 01 00 00 70 28 07 00 00 0a 28 0c 00 00 0a 26 00 de}  //weight: 1, accuracy: High
        $x_1_3 = {00 20 00 0c 00 00 28 0e 00 00 0a 00 06 02 6f 0f 00 00 0a 0b de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_GM_2147757416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.GM!MTB"
        threat_id = "2147757416"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 65 00 78 00 65 00 63 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 77 00 69 00 6e 00 64 00 6f 00 20 00 31 00 20 00 2d 00 6e 00 6f 00 [0-16] 65 00 78 00 69 00 74 00 20 00 2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 69 00 65 00 78 00 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 [0-200] 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 74 00 78 00 74 00 27 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_PE_2147761465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.PE!MTB"
        threat_id = "2147761465"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-nop -w hidden -e" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 6c 00 69 00 67 00 68 00 74 00 2d 00 62 00 69 00 6e 00 2e 00 74 00 6b 00 2f 00 72 00 61 00 77 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = "fud.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_A_2147767661_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.A!MTB"
        threat_id = "2147767661"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Release\\SqueLicenence.pdb" ascii //weight: 1
        $x_1_2 = "secretKey" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_AP_2147780095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.AP!MTB"
        threat_id = "2147780095"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0d 09 09 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 18 8d ?? ?? ?? 01 13 05 11 05 16 72 ?? ?? ?? 70 a2 11 05 14 14}  //weight: 10, accuracy: Low
        $x_4_2 = "@@!!##$$%%^^&&\\||L@@!!##$$%%^^&&\\||o@@!!##$$%%^^&&\\||a@@!!##$$%%^^&&\\||d" ascii //weight: 4
        $x_4_3 = "@@!!##$$%%^^&&\\||I@@!!##$$%%^^&&\\||n@@!!##$$%%^^&&\\||v@@!!##$$%%^^&&\\||o@@!!##$$%%^^&&\\||k@@!!##$$%%^^&&\\||e" ascii //weight: 4
        $x_3_4 = "@@!!##$$%%^^&&\\||" ascii //weight: 3
        $x_3_5 = "DownloadData" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Tiny_RC_2147781326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.RC!MTB"
        threat_id = "2147781326"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 09 07 09 1e d8 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 09 17 d6 0d 09 11 04 31 e4}  //weight: 10, accuracy: Low
        $x_5_2 = "nohing" ascii //weight: 5
        $x_3_3 = "Aderrrrrrrrrrrrrrrrrroooooooooolll" ascii //weight: 3
        $x_3_4 = "[^01]" ascii //weight: 3
        $x_3_5 = "webClient" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_RD_2147781330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.RD!MTB"
        threat_id = "2147781330"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -NoExit -Command" ascii //weight: 5
        $x_5_2 = "bitsadmin /transfer myDownloadJob /download /priority normal" ascii //weight: 5
        $x_5_3 = "/create /sc minute /mo 1 /tn" ascii //weight: 5
        $x_4_4 = "AddToSchtasks" ascii //weight: 4
        $x_4_5 = "schtasks" ascii //weight: 4
        $x_4_6 = "ProcessStartInfo" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_AMP_2147781620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.AMP!MTB"
        threat_id = "2147781620"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Microsoft Windows Protocol Services Host.exe" ascii //weight: 3
        $x_3_2 = "Microsoft Windows Protocol Monitor.exe" ascii //weight: 3
        $x_3_3 = "CreateDirectory" ascii //weight: 3
        $x_3_4 = "{Arguments If Needed}" ascii //weight: 3
        $x_3_5 = "StartUpApp" ascii //weight: 3
        $x_3_6 = "Microsoft Startup.lnk" ascii //weight: 3
        $x_3_7 = "CreateShortcut" ascii //weight: 3
        $x_3_8 = "Copy2" ascii //weight: 3
        $x_3_9 = "GetDirectoryName" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_AL_2147788953_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.AL!MTB"
        threat_id = "2147788953"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 05 00 00 06 0a 06 03 7d 01 00 00 04 16 06 7b 01 00 00 04 6f 1a 00 00 0a 28 1b 00 00 0a 7e 03 00 00 04 25 2d 17 26 7e 02 00 00 04 fe 06 09 00 00 06 73 1c 00 00 0a 25 80 03 00 00 04 28 01 00 00 2b 06 fe 06 06 00 00 06 73 1e 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 2a}  //weight: 10, accuracy: High
        $x_3_2 = "DownloadString" ascii //weight: 3
        $x_3_3 = "powershell.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_HJKL_2147793618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.HJKL!MTB"
        threat_id = "2147793618"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://transfer.sh/get/" ascii //weight: 1
        $x_1_2 = "/k START" ascii //weight: 1
        $x_1_3 = "powershell" ascii //weight: 1
        $x_1_4 = "Set-MpPreference -ExclusionExtension" ascii //weight: 1
        $x_1_5 = "Start-Sleep -s" ascii //weight: 1
        $x_1_6 = "curl.exe -o" ascii //weight: 1
        $x_1_7 = "--url" ascii //weight: 1
        $x_1_8 = "Exploit" ascii //weight: 1
        $x_1_9 = "set_UseShellExecute" ascii //weight: 1
        $x_1_10 = "& EXIT" ascii //weight: 1
        $x_1_11 = "GetHashCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_MA_2147808547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.MA!MTB"
        threat_id = "2147808547"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://pastebin.com/raw/dvEykWim" ascii //weight: 1
        $x_1_2 = "c:\\temp\\Assembly.exe" ascii //weight: 1
        $x_1_3 = "C:\\Documents and Settings\\JohnDoe\\Application Data\\tool.exe" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DownloadString" ascii //weight: 1
        $x_1_8 = "get_Network" ascii //weight: 1
        $x_1_9 = "get_User" ascii //weight: 1
        $x_1_10 = "D:\\CodingGuy Backup2\\repos\\DROPPER\\DROPPER\\obj\\Release\\d.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_RK_2147819138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.RK!MTB"
        threat_id = "2147819138"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionExtension \"exe\"" wide //weight: 1
        $x_1_2 = "https://cdn.discordapp.com/attachments/917039201843834961/917039259670700042/Loader_Link_Changer.exe" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "WriteAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ARA_2147837237_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ARA!MTB"
        threat_id = "2147837237"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 06 07 11 05 11 06 1b 58 11 04 11 06 59 20 00 10 00 00 3c ?? ?? ?? 00 11 04 11 06 59 38 ?? ?? ?? 00 20 00 10 00 00 16 6f ?? ?? ?? 0a 58 13 06 11 06 11 04 3f ?? ?? ?? ff}  //weight: 4, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ARAQ_2147838169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ARAQ!MTB"
        threat_id = "2147838169"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1a 2c 2b 11 04 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f ?? ?? ?? 0a 11 05 17 58 13 05 11 05 08 8e 69 32 db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_NTD_2147838208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.NTD!MTB"
        threat_id = "2147838208"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 06 00 00 0a 0a 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 26 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {06 6a 20 00 00 00 80 6e 5f 20 ?? ?? ?? 80 6e 33 0c 06 17 62 20 ?? ?? ?? 04 61 0a 2b 04 06 17 62 0a 09 17 58 0d 09 1e 32 d7}  //weight: 5, accuracy: Low
        $x_1_3 = "ProcessWindowStyle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_RDA_2147839951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.RDA!MTB"
        threat_id = "2147839951"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5f436ec0-de58-4c5e-88bc-f1263e9297ab" ascii //weight: 1
        $x_1_2 = "//l5715.in/1.exe" wide //weight: 1
        $x_1_3 = "Izohyrz" ascii //weight: 1
        $x_1_4 = "MSEInstall Package" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ATY_2147841822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ATY!MTB"
        threat_id = "2147841822"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 2b 22 00 06 6f 17 00 00 0a 07 9a 6f 18 00 00 0a 14 14 6f 19 00 00 0a 2c 02 de 0e de 03 26 de 00 07 17 58 0b 07 1f 0a 32 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ATY_2147841822_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ATY!MTB"
        threat_id = "2147841822"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 11 04 6f ?? ?? ?? 0a 8c 01 00 00 01 28 ?? ?? ?? 0a 13 05 11 05 28 ?? ?? ?? 06 39 03 00 00 00 11 05 2a 11 04 17 58 13 04 11 04 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ATY_2147841822_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ATY!MTB"
        threat_id = "2147841822"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 0d 2b 3b 00 08 13 04 16 13 05 11 04 12 05 28 ?? ?? ?? 0a 00 08 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 de 0d 11 05 2c 08 11 04 28 ?? ?? ?? 0a 00 dc 00 09 18 58 0d 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d b6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ABVO_2147846882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ABVO!MTB"
        threat_id = "2147846882"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 07 09 1a 16 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 11 04 1b 58 8d ?? 00 00 01 13 05 16 13 06 38 ?? 00 00 00 11 06 07 11 05 11 06 1b 58 11 04 11 06 59 20 00 10 00 00 3c ?? 00 00 00 11 04 11 06 59 38 ?? 00 00 00 20 00 10 00 00 16 6f ?? 00 00 0a 58 13 06 11 06 11 04}  //weight: 3, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_AT_2147847843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.AT!MTB"
        threat_id = "2147847843"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 03 00 00 0a 0a 06 6f 04 00 00 0a 72 01 00 00 70 6f 05 00 00 0a 06 6f 04 00 00 0a 72 11 00 00 70 6f 06 00 00 0a 06 6f 04 00 00 0a 17 6f 07 00 00 0a 06 6f 04 00 00 0a 17 6f 08 00 00 0a 06 6f 09 00 00 0a 26 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_AT_2147847843_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.AT!MTB"
        threat_id = "2147847843"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0c 00 08 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 07 09 28 ?? 00 00 0a 00 00 de 0b}  //weight: 2, accuracy: Low
        $x_1_2 = "WindowsSetupManger\\obj\\Debug\\WindowsSetupManger.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_AT_2147847843_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.AT!MTB"
        threat_id = "2147847843"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 11 05 11 04 16 9a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 06 11 05 11 04 17 9a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 07 11 06 11 06 6f ?? ?? ?? 0a 17 59 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 08 28 ?? ?? ?? 0a 11 08 6f ?? ?? ?? 0a 13 06 11 06 11 07}  //weight: 2, accuracy: Low
        $x_1_2 = "de-CH-pleasenorun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_PAAH_2147850039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.PAAH!MTB"
        threat_id = "2147850039"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$b2077f96-6a93-45f9-bb79-81b7e7a5661c" ascii //weight: 1
        $x_1_2 = "//144.202.7.42/dddddd?a=1" wide //weight: 1
        $x_1_3 = "WScript.echo('da');" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_PAAI_2147850040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.PAAI!MTB"
        threat_id = "2147850040"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nikivprivates.7m.pl/database/config/lopik.exe" wide //weight: 1
        $x_1_2 = "C:\\systemfat.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ARAF_2147850733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ARAF!MTB"
        threat_id = "2147850733"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 06 09 1e 5a 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 00 09 17 58 0d 09 07 8e 69 17 59 fe 02 16 fe 01 13 04 11 04}  //weight: 2, accuracy: Low
        $x_2_2 = "\\Njrat\\obj\\Debug\\Njrat.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ATN_2147892031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ATN!MTB"
        threat_id = "2147892031"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 08 1f 2a 1f ?? 8c 07 00 00 01 a2 08 1f 2b 1f ?? 8c 07 00 00 01 a2 08 1f 2c 1f ?? 8c 07 00 00 01 a2 08 1f 2d 1f ?? 8c 07 00 00 01 a2 08 1f 2e 1f ?? 8c 07 00 00 01 a2 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_ATN_2147892031_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.ATN!MTB"
        threat_id = "2147892031"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 17 6f ?? 00 00 0a 2d 2a 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 02 28 ?? 00 00 06 02 28 ?? 00 00 06 02 28}  //weight: 2, accuracy: Low
        $x_1_2 = "pycsharp\\pycsharp\\obj\\Release\\pycsharp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_APB_2147896069_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.APB!MTB"
        threat_id = "2147896069"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/C choice /C Y /N /D Y /T 3 & Del" ascii //weight: 5
        $x_5_2 = "finalres.vbs" ascii //weight: 5
        $x_4_3 = "RemoveEXE" ascii //weight: 4
        $x_4_4 = "TOKEN_STEALER_CREATOR" ascii //weight: 4
        $x_4_5 = "GetTempPath" ascii //weight: 4
        $x_4_6 = "WebClient" ascii //weight: 4
        $x_4_7 = "DownloadFile" ascii //weight: 4
        $x_4_8 = "discord" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_4_*))) or
            ((2 of ($x_5_*) and 5 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Tiny_KA_2147896225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.KA!MTB"
        threat_id = "2147896225"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 0a 0b 07 72 ?? 00 00 70 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0c 08 06 28 ?? 00 00 0a 08 28 ?? 00 00 0a 26 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "WriteAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_MVD_2147901311_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.MVD!MTB"
        threat_id = "2147901311"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 28 08 00 00 0a 07 6f 09 00 00 0a 6f 0a 00 00 0a 0c}  //weight: 2, accuracy: High
        $x_1_2 = "allstarprivate.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_MVE_2147901633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.MVE!MTB"
        threat_id = "2147901633"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upload.ee/download/" ascii //weight: 1
        $x_1_2 = "Hallaj.txt" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_5_4 = "fghfgfdg.exe" ascii //weight: 5
        $x_5_5 = "dawnloedkla.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Tiny_SGC_2147901816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.SGC!MTB"
        threat_id = "2147901816"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 1c 28 11 00 00 0a 72 e5 09 00 70 28 12 00 00 0a 28 04 00 00 06 00 09 28 15 00 00 0a 26 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_SGB_2147901818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.SGB!MTB"
        threat_id = "2147901818"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadData" ascii //weight: 1
        $x_1_2 = "damn.RunPE" wide //weight: 1
        $x_1_3 = "catlak" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_SGD_2147901901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.SGD!MTB"
        threat_id = "2147901901"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 04 28 01 00 00 06 02 28 02 00 00 06 00 00 2b 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_MVG_2147902178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.MVG!MTB"
        threat_id = "2147902178"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 03 00 00 0a 72 01 00 00 70 28 04 00 00 0a 28 05 00 00 0a 72 31 00 00 70 6f 06 00 00 0a 72 53 00 00 70 6f 07 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_MVH_2147902179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.MVH!MTB"
        threat_id = "2147902179"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 72 01 00 00 70 72 71 00 00 70 6f 04 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tiny_MVF_2147902433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tiny.MVF!MTB"
        threat_id = "2147902433"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 0f 00 00 70 28 04 00 00 06 0b 07 28 08 00 00 06}  //weight: 1, accuracy: High
        $x_1_2 = "Sliver_stager.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


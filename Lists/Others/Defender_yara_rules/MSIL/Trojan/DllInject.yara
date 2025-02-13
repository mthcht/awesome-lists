rule Trojan_MSIL_DllInject_A_2147759386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.A!MTB"
        threat_id = "2147759386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 00 20 e8 80 00 00 28 ?? ?? ?? ?? 00 38 00 00 00 00 02 04 28 04 00 00 06 28 03 00 00 06 03 28 02 00 00 06 28 01 00 00 06 0a 06 28}  //weight: 10, accuracy: Low
        $x_1_2 = "AndroidStudio.dll" wide //weight: 1
        $x_1_3 = "GetEntryAssembly" ascii //weight: 1
        $x_1_4 = "get_EntryPoint" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DllInject_D_2147759388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.D!MTB"
        threat_id = "2147759388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZtO3Ntb2tldGVzdA==" wide //weight: 1
        $x_1_2 = "AndroidStudio" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_I_2147759689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.I!MTB"
        threat_id = "2147759689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 11 00 20 e8 80 00 00 28 27 00 00 0a 00 [0-10] 02 04 28 04 00 00 06 28 03 00 00 06 [0-10] 03 28 02 00 00 06 28 01 00 00 06 0a 06 28 28 00 00 0a 6f 29 00 00 0a 16 8c 23 00 00 01 14 6f 2a 00 00 0a 26 16 28 2b 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {05 00 00 11 00 20 ?? ?? 00 00 28 27 00 00 0a 00 [0-10] 02 04 28 04 00 00 06 28 03 00 00 06 [0-10] 03 28 02 00 00 06 28 01 00 00 06 0a 06 28 28 00 00 0a 6f 29 00 00 0a 16 8c 23 00 00 01 14 6f 2a 00 00 0a 26 16 28 2b 00 00}  //weight: 1, accuracy: Low
        $x_10_3 = "AndroidStudio.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DllInject_J_2147761180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.J!MTB"
        threat_id = "2147761180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AndroidStudio.dll" ascii //weight: 4
        $x_3_2 = "Sparta.dll" ascii //weight: 3
        $x_2_3 = "XOR_Decrypt" ascii //weight: 2
        $x_1_4 = "InsertRange" ascii //weight: 1
        $x_1_5 = "System.IO.Compression" ascii //weight: 1
        $x_1_6 = "Resource_Func" ascii //weight: 1
        $x_1_7 = "StartGame" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DllInject_BAE_2147798540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.BAE!MTB"
        threat_id = "2147798540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Browser_JavascriptMessageReceived>b__22_0" ascii //weight: 1
        $x_1_2 = "<AnimateInjected>d__53" ascii //weight: 1
        $x_1_3 = "svg321_Copy3" ascii //weight: 1
        $x_1_4 = "FileHBOptsGate" ascii //weight: 1
        $x_1_5 = "FolderDisplay_MouseLeave" ascii //weight: 1
        $x_1_6 = "CardHolder_MouseDoubleClick" ascii //weight: 1
        $x_1_7 = "KrnlUI.exe" ascii //weight: 1
        $x_1_8 = "KrnlUI-main\\KrnlUI\\obj\\Release\\KrnlUI.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_CB_2147828664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.CB!MTB"
        threat_id = "2147828664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Did the dll properly inject?" wide //weight: 1
        $x_1_2 = "Did your fireall block us?" wide //weight: 1
        $x_1_3 = "Please be sure yout anti-virus is disabled then restart the exploit" wide //weight: 1
        $x_1_4 = "DLL failed to inject" wide //weight: 1
        $x_1_5 = "qdRFzx.exe" wide //weight: 1
        $x_1_6 = "deleteme" wide //weight: 1
        $x_1_7 = "Module2.dll" wide //weight: 1
        $x_1_8 = "cdn.wearedevs.net/scripts/BTools.txt" wide //weight: 1
        $x_1_9 = "exploit-main.dll" wide //weight: 1
        $x_1_10 = "finj.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_CC_2147831372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.CC!MTB"
        threat_id = "2147831372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Internet Explorer\\Internet Explorer\\Skriller.exe" wide //weight: 1
        $x_1_2 = "M:\\YEDEK\\Yedek\\Dosyalar\\EXE - 2012\\muzun\\AutoSig_source\\AutoSig\\obj\\Debug\\mhuzun.pdb" ascii //weight: 1
        $x_1_3 = "RegisterBHO" ascii //weight: 1
        $x_1_4 = "$5ADEFB9E-B824-45e6-86E2-2B7941F5D6A3" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_NEAA_2147836724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.NEAA!MTB"
        threat_id = "2147836724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "https://shoppy.gg/product/l8TIeQD" wide //weight: 5
        $x_5_2 = "https://pastebin.com/raw/XpSn8yGq" wide //weight: 5
        $x_5_3 = "rblxexploits.com" wide //weight: 5
        $x_5_4 = "FurkUltra" wide //weight: 5
        $x_5_5 = "lua.xshd" wide //weight: 5
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_NEAB_2147837434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.NEAB!MTB"
        threat_id = "2147837434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "8ce665e4-c513-4afb-a651-2a02c504a983" ascii //weight: 5
        $x_5_2 = "Precision.dll" ascii //weight: 5
        $x_2_3 = "Bannionest" ascii //weight: 2
        $x_2_4 = "Tweeter" ascii //weight: 2
        $x_1_5 = "Management consultant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_AD_2147838880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.AD!MTB"
        threat_id = "2147838880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 16 0c 2b 12 07 08 9a 25 6f 09 00 00 0a 6f 0a 00 00 0a 08 17 58 0c 08 07 8e 69 32 e8}  //weight: 2, accuracy: High
        $x_1_2 = "Updater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_MA_2147840323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.MA!MTB"
        threat_id = "2147840323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 9a 0d 00 09 6f ?? ?? ?? 0a 72 0b 00 00 70 28 ?? ?? ?? 0a 13 04 11 04 13 05 11 05 2c 09 00 09}  //weight: 5, accuracy: Low
        $x_1_2 = "LaunchExploit" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "Roblox_Executor_WolfCheats.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_MA_2147840323_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.MA!MTB"
        threat_id = "2147840323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 95 a2 21 09 03 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 51 00 00 00 08 00 00 00 2d 00 00 00 1d 00 00 00 1f}  //weight: 5, accuracy: High
        $x_1_2 = "Orange_Tech.Properties" ascii //weight: 1
        $x_1_3 = "2bc7f387-fbbf-41a1-9974-66b71f31f776" ascii //weight: 1
        $x_1_4 = "LaunchExploit" ascii //weight: 1
        $x_1_5 = "scripts_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_MBCQ_2147844454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.MBCQ!MTB"
        threat_id = "2147844454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 59 17 58 6f ?? 00 00 0a 13 07 11 05 11 07 1b 8d ?? 00 00 01 13 0a 11 0a 16 72 3d 01 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_MBDZ_2147845785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.MBDZ!MTB"
        threat_id = "2147845785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 11 05 17 06 1e 58 4a 17 59 6f ?? 00 00 0a 25 1f 7a 6f ?? 00 00 0a 16 fe 04 16 fe 01 13 06 1f 74 6f 59 00 00 0a 16 fe 04 16 fe 01 13 07 11 05 06 1e 58 4a 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = "Ldaadpdlkqo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_MBCC_2147845796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.MBCC!MTB"
        threat_id = "2147845796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 5b 33 49 06 1e 58 11 05 1f 5d 6f ?? 00 00 0a 54 11 05 17 06 1e 58 4a 17 59 6f ?? 00 00 0a 25 1f 7a 6f 86 00 00 0a 16 fe 04 16 fe 01 13 06 1f 74 6f ?? 00 00 0a 16 fe 04 16 fe 01 13 07 11 05 06 1e 58 4a}  //weight: 1, accuracy: Low
        $x_1_2 = "Askglqenlhu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_MBFF_2147849966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.MBFF!MTB"
        threat_id = "2147849966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 13 06 38 00 00 00 00 03 16 e0 28 ?? 00 00 0a 16 09 08 16 12 00 28 ?? 00 00 06 13 04 16 13 07 38 00 00 00 00 11 04 20 10 27 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "c253521f3d03" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DllInject_JB_2147895549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DllInject.JB!MTB"
        threat_id = "2147895549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 10 00 00 0a 2c 3e 72 0b 00 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


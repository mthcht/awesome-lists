rule Trojan_MSIL_Bsymem_W_2147782477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bsymem.W!MTB"
        threat_id = "2147782477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BypassSilentCleanup" ascii //weight: 3
        $x_3_2 = "BypassEventvwr" ascii //weight: 3
        $x_3_3 = "BypassFodhelper" ascii //weight: 3
        $x_3_4 = "/Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I" ascii //weight: 3
        $x_3_5 = "UAC Bypass Application Executed" ascii //weight: 3
        $x_3_6 = "IsRunningAsLocalAdmin" ascii //weight: 3
        $x_3_7 = "ConsentPromptBehaviorAdmin" ascii //weight: 3
        $x_3_8 = "/C powershell Add-MpPreference -ExclusionExtension .exe -Force" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bsymem_ADA_2147783529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bsymem.ADA!MTB"
        threat_id = "2147783529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 16 0c 2b 17 06 08 8f ?? 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 08 17 58 0c 08 06 8e 69 17 59 32 e1}  //weight: 10, accuracy: Low
        $x_3_2 = "/c taskkill /im" ascii //weight: 3
        $x_3_3 = ".exe\" /f & erase" ascii //weight: 3
        $x_3_4 = "CheckFile" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bsymem_NEAA_2147838074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bsymem.NEAA!MTB"
        threat_id = "2147838074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "2E917BA0-D5EC-4EF7-81F1-6C7E52BCAFA1" ascii //weight: 5
        $x_5_2 = "Aiview.exe" wide //weight: 5
        $x_2_3 = "Powered by SmartAssembly 8.1.2.4975" ascii //weight: 2
        $x_2_4 = "SmartAssembly.HouseOfCards" ascii //weight: 2
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bsymem_NB_2147839769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bsymem.NB!MTB"
        threat_id = "2147839769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 45 00 00 06 17 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 20 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 2c 0a 28 ?? ?? ?? 06 38 ?? ?? ?? 00 7e ?? ?? ?? 04 20 ?? ?? ?? 06 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "ReadProcessMemory" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Bandizip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bsymem_NBY_2147841372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bsymem.NBY!MTB"
        threat_id = "2147841372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 01 09 51 15 61 20 ?? ?? ?? 2b 40 ?? ?? ?? 00 20 ?? ?? ?? 00 fe ?? ?? 00 fe ?? ?? ?? ?? 01 58 00 fe ?? ?? 00 8e 69 6f ?? ?? ?? 0a fe ?? ?? 00 20 ?? ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 20 ?? ?? ?? 5f 20 ?? ?? ?? 51 61 20 ?? ?? ?? 0e}  //weight: 5, accuracy: Low
        $x_1_2 = "Moietykors" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bsymem_SPCS_2147847945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bsymem.SPCS!MTB"
        threat_id = "2147847945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 08 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 28 ?? ?? ?? 0a 72 01 00 00 70 6f ?? ?? ?? 0a 0d d0 22 00 00 01 28 ?? ?? ?? 0a 09 72 4d 00 00 70 28 ?? ?? ?? 0a 16 8d 10 00 00 01 6f ?? ?? ?? 0a 26 de 1e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bsymem_AAMO_2147888801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bsymem.AAMO!MTB"
        threat_id = "2147888801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 16 08 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 13 05 11 05}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bsymem_AMAA_2147889484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bsymem.AMAA!MTB"
        threat_id = "2147889484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 10 17 8d ?? ?? 00 01 25 16 11 05 11 10 9a 1f 10 28 ?? 00 00 0a 86 9c 6f ?? 00 00 0a 00 11 10 17 d6 13 10 11 10 11 0f 31 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


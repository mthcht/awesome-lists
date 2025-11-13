rule Trojan_Win64_Khalesi_AM_2147817184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.AM!MTB"
        threat_id = "2147817184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 77 81 e9 ce 00 00 00 44 8b 45 07 41 03 d4 44 8b 4d ff 41 81 e8 1f 08 00 00 8b 75 7f 41 81 e9 b6 06 00 00 8b 7d 03 81 c6 f3 09 00 00 8b 5d fb 03 f8 44 8b 5d ff 81 eb dc 06 00 00 44 8b 55 03 41 81 eb 13 06 00 00}  //weight: 10, accuracy: High
        $x_3_2 = "KrrQFWGYWN" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_DA_2147817355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.DA!MTB"
        threat_id = "2147817355"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "KrrQFWGYWN" ascii //weight: 10
        $x_10_2 = "xshiMECwuG" ascii //weight: 10
        $x_1_3 = "GetComputerNameA" ascii //weight: 1
        $x_1_4 = "SwitchToFiber" ascii //weight: 1
        $x_1_5 = "DeleteFiber" ascii //weight: 1
        $x_1_6 = "ResumeThread" ascii //weight: 1
        $x_1_7 = "GetModuleFileNameA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Khalesi_AN_2147817363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.AN!MTB"
        threat_id = "2147817363"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YTBSBbNTWU" ascii //weight: 3
        $x_2_2 = "GetComputerNameA" ascii //weight: 2
        $x_2_3 = "SwitchToFiber" ascii //weight: 2
        $x_2_4 = "DeleteFiber" ascii //weight: 2
        $x_2_5 = "ResumeThread" ascii //weight: 2
        $x_2_6 = "GetModuleFileNameA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_DB_2147817803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.DB!MTB"
        threat_id = "2147817803"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ZmJwfQQnqA" ascii //weight: 10
        $x_1_2 = "GetTempPathA" ascii //weight: 1
        $x_1_3 = "SwitchToFiber" ascii //weight: 1
        $x_1_4 = "CreateFiber" ascii //weight: 1
        $x_1_5 = "CallNamedPipeA" ascii //weight: 1
        $x_1_6 = "GetModuleFileNameA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_CCGG_2147900549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.CCGG!MTB"
        threat_id = "2147900549"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ollydbg.exe" ascii //weight: 1
        $x_1_2 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_3 = "procmon.exe" ascii //weight: 1
        $x_1_4 = "idaq.exe" ascii //weight: 1
        $x_1_5 = "windbg.exe" ascii //weight: 1
        $x_1_6 = "taskkill /f /im HTTPDebuggerSvc.exe" ascii //weight: 1
        $x_1_7 = "taskkill /FI \"IMAGENAME eq httpdebugger" ascii //weight: 1
        $x_1_8 = "taskkill /FI \"IMAGENAME eq processhacker" ascii //weight: 1
        $x_1_9 = "taskkill /FI \"IMAGENAME eq fiddler" ascii //weight: 1
        $x_1_10 = "taskkill /FI \"IMAGENAME eq wireshark" ascii //weight: 1
        $x_1_11 = "taskkill /FI \"IMAGENAME eq ida*" ascii //weight: 1
        $x_1_12 = "sc stop HTTPDebuggerPro" ascii //weight: 1
        $x_1_13 = "sc stop wireshark" ascii //weight: 1
        $x_1_14 = "Enter License :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_GNZ_2147901242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.GNZ!MTB"
        threat_id = "2147901242"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 89 c1 45 31 c0 31 d2 4c 8d 64 24 42 31 c9 48 89 de e8}  //weight: 10, accuracy: High
        $x_10_2 = {56 53 48 83 ec 50 48 8b 2d ?? ?? ?? ?? 45 31 c9 45 31 c0 31 d2 48 8b 45 00 48 89 44 24 48 31 c0 48 8d 74 24 3c 31 c0 48 89 cf 48 89 74 24 20 31 c9 89 44 24 3c e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_AMMB_2147904303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.AMMB!MTB"
        threat_id = "2147904303"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 39 cf 74 ?? 8d 45 01 99 f7 fe 4c 63 ea 42 0f b6 84 2c ?? ?? ?? ?? 4b 8d 0c 2a 4c 89 ed 44 01 e0 99 f7 fe 4c 63 f2 4b 8d 14 32 4d 89 f4 e8 ?? ?? ?? ?? 42 8a 8c 34 ?? ?? ?? ?? 42 02 8c 2c ?? ?? ?? ?? 0f b6 c9 8a 84 0c ?? ?? ?? ?? 41 30 01 49 ff c1 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_RK_2147905865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.RK!MTB"
        threat_id = "2147905865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 39 d0 74 14 49 89 c0 41 83 e0 1f 46 8a 04 ?? 44 30 04 01 48 ff c0 eb e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_RU_2147912244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.RU!MTB"
        threat_id = "2147912244"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 40 48 8b 1d ?? ?? ?? ?? 0f 29 74 24 30 0f 29 7c 24 20 80 3b 00 75 1a 41 b8 b6 23 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "Imgui Design V3\\Imgui Design V3\\Imgui Design V3\\examples\\Exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_RZ_2147912416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.RZ!MTB"
        threat_id = "2147912416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 65 00 78 00 61 00 6d 00 70 00 6c 00 65 00 73 00 5c 00 65 00 78 00 61 00 6d 00 70 00 6c 00 65 00 5f 00 77 00 69 00 6e 00 33 00 32 00 5f 00 64 00 69 00 72 00 65 00 63 00 74 00 78 00 31 00 31 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 42 00 4c 00 41 00 43 00 4b 00 20 00 42 00 55 00 4c 00 4c 00 [0-16] 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 65 78 61 6d 70 6c 65 73 5c 65 78 61 6d 70 6c 65 5f 77 69 6e 33 32 5f 64 69 72 65 63 74 78 31 31 5c 52 65 6c 65 61 73 65 5c 42 4c 41 43 4b 20 42 55 4c 4c [0-16] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 41 8b fe 41 8b de 8d 4a 02 ff 15 ?? ?? ?? 00 48 8d 54 24 20 c7 44 24 20 30 01 00 00 48 8b c8 48 8b f0 ff 15 ?? ?? ?? 00 48 8d 54 24 20 48 8b ce ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Khalesi_ARAZ_2147929778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.ARAZ!MTB"
        threat_id = "2147929778"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {89 c1 44 0f b6 44 0c 34 8d 50 77 83 c0 01 44 31 c2 88 54 0c 34 8b 54 24 30 39 c2 77 e3}  //weight: 4, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_PGKH_2147955107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi.PGKH!MTB"
        threat_id = "2147955107"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://files.catbox.moe/k6m4s4.bat" ascii //weight: 2
        $x_2_2 = "https://files.catbox.moe/l3whjb.wav" ascii //weight: 2
        $x_2_3 = "https://files.catbox.moe/lg2jiw.bat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Khalesi_AMTB_2147955742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Khalesi!AMTB"
        threat_id = "2147955742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Khalesi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ANTI_DISASSM" ascii //weight: 1
        $x_1_2 = "CODE_INJECTIONS" ascii //weight: 1
        $x_1_3 = "TIMING_ATTACKS" ascii //weight: 1
        $x_1_4 = "al-khaser.pdb" ascii //weight: 1
        $x_1_5 = "Injected library: %S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_SquirrelWaffle_ES_2147794051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquirrelWaffle.ES!MTB"
        threat_id = "2147794051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquirrelWaffle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Semiarid" ascii //weight: 3
        $x_3_2 = "I:\\piepoudre.pdb" ascii //weight: 3
        $x_3_3 = "P:\\osiery.pdb" ascii //weight: 3
        $x_3_4 = "G:\\sectionary.pdb" ascii //weight: 3
        $x_3_5 = "nursy\\dazzler" ascii //weight: 3
        $x_3_6 = "GetTempPathW" ascii //weight: 3
        $x_3_7 = "RemoveDirectoryW" ascii //weight: 3
        $x_3_8 = "OutputDebugStringA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SquirrelWaffle_EM_2147794052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquirrelWaffle.EM!MTB"
        threat_id = "2147794052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquirrelWaffle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {51 8d 4c 24 04 2b c8 1b c0 f7 d0 23 c8 8b c4 25 00 f0 ff ff}  //weight: 10, accuracy: High
        $x_3_2 = "Broadcom NetXtreme Gigabit Ethernet" ascii //weight: 3
        $x_3_3 = "vZDItAZHvdWdZiJfILEAgWHMOVukxJQnljINIVoJnFdhQTsgNPmruyZb" ascii //weight: 3
        $x_3_4 = "APPDATA" ascii //weight: 3
        $x_3_5 = "c\\hjmTP" ascii //weight: 3
        $x_3_6 = "Dll1.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SquirrelWaffle_B_2147794258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquirrelWaffle.B"
        threat_id = "2147794258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquirrelWaffle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hypsoisotherm.dll" ascii //weight: 1
        $x_1_2 = "doited.pdb" ascii //weight: 1
        $x_1_3 = "heterozygousness.pdb" ascii //weight: 1
        $x_1_4 = "lazaret.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SquirrelWaffle_DA_2147794670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquirrelWaffle.DA"
        threat_id = "2147794670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquirrelWaffle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Actcause" ascii //weight: 1
        $x_1_2 = "Breakbox" ascii //weight: 1
        $x_1_3 = "CauseSeat" ascii //weight: 1
        $x_1_4 = "Duringweight" ascii //weight: 1
        $x_1_5 = "Equalcry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_SquirrelWaffle_DB_2147794671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquirrelWaffle.DB"
        threat_id = "2147794671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquirrelWaffle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ea 02 0f b6 c8 8a c3 2b ce 83 e9 2e 2a c1 89 0d ?? ?? ?? ?? 04 08 a2 ?? ?? ?? ?? 83 fa 02 07 00 29 34 95}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 cb 66 8b c1 66 03 c0 66 03 c8 8b 44 24 ?? 05 98 89 0b 01 66 2b ce 83 6c 24 ?? 01 89 07 8b 7c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


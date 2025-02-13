rule Trojan_Win32_KillProc_A_2147628528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillProc.A"
        threat_id = "2147628528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 f8 05 7e 20 80 3e 70 75 1b 80 7e 01 63 75 15 80 7c 30 fd 72 75 0e 80 7c 30 fe 65 75 07 80 7c 30 ff 67 74 0b}  //weight: 10, accuracy: High
        $x_10_2 = {8a 1c 0e 32 9a ?? ?? ?? 10 83 c2 01 3b d5 88 5c 0e ff 75 02 33 d2 83 c1 01 3b cf 7e e3}  //weight: 10, accuracy: Low
        $x_1_3 = "ConditionalKiller.dll" ascii //weight: 1
        $x_1_4 = "TransactNamedPipe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KillProc_BD_2147837419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillProc.BD!MTB"
        threat_id = "2147837419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 6a 01 8d 55 dc 6a 01 52 e8 [0-4] 80 75 dc fb 56 6a 01 8d 45 dc 6a 01 50 e8 [0-4] 43 83 c4 20 3b 9d 6c fd ff ff 72}  //weight: 2, accuracy: Low
        $x_2_2 = "SogouPinyin.local" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillProc_DAL_2147849959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillProc.DAL!MTB"
        threat_id = "2147849959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2a ea ba 49 e9 c6 a0 9e 40 d2 1a ce d2 cf 2b 22 25 4a 1f 2e ad 18 48 d0 33 36 1b a6 bf 84 fb e7 f9 02 fc 0c ec 7e}  //weight: 2, accuracy: High
        $x_2_2 = {5c ae 52 36 a6 49 31 d8 d6 8e 16 15 d5 f1 b5 74 01 a1 8b 54 80 cc 82 de b5 be aa 05 73 c3 af 50 fa 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillProc_MA_2147921689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillProc.MA!MTB"
        threat_id = "2147921689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 07 85 c0 74 03 89 78 04 89 3d 20 86 41 00 68 24 86 41 00 ff 15 14 75 41 00}  //weight: 5, accuracy: High
        $x_1_2 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_3 = "DisableAntiVirus" ascii //weight: 1
        $x_1_4 = "EnableLUA /t REG_DWORD /d 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KillProc_NS_2147929304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillProc.NS!MTB"
        threat_id = "2147929304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 80 e6 44 00 e8 ?? ?? ?? ?? 8d 45 fc 50 68 06 00 02 00 6a 00 68 8c e6 44 00 68 02 00 00 80 e8 ?? ?? ?? ?? 83 7d fc 00 75 28}  //weight: 2, accuracy: Low
        $x_3_2 = {8d 55 b0 8b c6 e8 ?? ?? ?? ?? ff 75 b0 68 20 eb 44 00 8b 45 fc ff 34 d8 8d 45 b4 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 55 b4 b8 f8 ea 44 00 e8}  //weight: 3, accuracy: Low
        $x_1_3 = "kill123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_ZLoader_RZ_2147758548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.RZ!MTB"
        threat_id = "2147758548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\anger\\fit\\Shell\\Far\\Women\\deal\\fire.pdb" ascii //weight: 1
        $x_1_2 = "fire.dll" ascii //weight: 1
        $x_1_3 = "Chief" ascii //weight: 1
        $x_1_4 = "rpr/dnu8itecpo6 cnvmrlnEno" ascii //weight: 1
        $x_1_5 = "h60oedVidmr3/w iiR5dn6rnlSVoeymo brS" ascii //weight: 1
        $x_1_6 = "oncc3u610rea iexim5wmer1o 0daWi.M0kibi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZLoader_DA_2147767279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.DA!MTB"
        threat_id = "2147767279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\IXP000.TMP\\" ascii //weight: 1
        $x_1_2 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32 \"%s\"" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_4 = "cmd /c tim.bat" ascii //weight: 1
        $x_1_5 = "Command.com /c %s" ascii //weight: 1
        $x_1_6 = "GetTempPathA" ascii //weight: 1
        $x_1_7 = "DoInfInstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZLoader_A_2147777757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.A"
        threat_id = "2147777757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 84 c0 74 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 [0-30] 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 55 08 89 d0 35 [0-8] 0f af ca}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 89 d0 35 [0-8] 80 cb}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ec 70 03 00 00 8b ?? ?? 8b ?? ?? 68 6f 03 00 00 [0-8] 83 c4 04 89 ?? 89}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 ff d0 85 c0 14 00 [0-8] 68 ?? ?? ?? ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ZLoader_A_2147777758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.A!!ZLoader.A"
        threat_id = "2147777758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "ZLoader: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 84 c0 74 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 [0-30] 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 55 08 89 d0 35 [0-8] 0f af ca}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 89 d0 35 [0-8] 80 cb}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ec 70 03 00 00 8b ?? ?? 8b ?? ?? 68 6f 03 00 00 [0-8] 83 c4 04 89 ?? 89}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 ff d0 85 c0 14 00 [0-8] 68 ?? ?? ?? ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ZLoader_MMC_2147919179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.MMC!MTB"
        threat_id = "2147919179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b f3 c1 ee 05 03 75 e4 03 fa 03 c3 33 f8 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 5, accuracy: Low
        $x_5_2 = {c1 e9 05 03 4d e8 c7 05 ?? ?? ?? ?? 84 10 d6 cb 33 cf 33 ce c7 05 ?? ?? ?? ?? ff ff ff ff 2b d9 8b 45 ec 29 45 f8 83 6d f4 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZLoader_FLE_2147920449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.FLE!MTB"
        threat_id = "2147920449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 d9 0f b6 c1 8a 14 06 88 14 2e 88 1c 06 0f b6 04 2e 01 d8 0f b6 c0 8a 04 06 8b 74 24 08 30 07 47 4e 75 c4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZLoader_BLG_2147920450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.BLG!MTB"
        threat_id = "2147920450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 f0 c1 e0 04 01 f0 b9 01 00 00 00 29 c1 03 0d ?? ?? ?? ?? 0f b6 5c 0f ff 8b 4d ec 41 8b 45 08 32 1c 38 8b 45 0c 88 1c 38 8d 7f 01 74}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZLoader_MJJ_2147921733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.MJJ!MTB"
        threat_id = "2147921733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d6 8a 04 0e 88 04 1e 8b 55 dc 88 14 0e 8b 4d 08 0f b6 04 1e 01 d0 0f b6 c0 8a 04 06 30 04 39 47 ff 75 0c 57 e8 ?? ?? ?? ?? 83 c4 08 a8 01 0f 84}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZLoader_AAB_2147930846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.AAB!MTB"
        threat_id = "2147930846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {57 50 e8 fd dd ?? ?? 8b 4d ec 83 c4 08 23 45 f0 21 ?? 8b 75 10 0f b6 04 06 30 01 41 8b 45 e8 48 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


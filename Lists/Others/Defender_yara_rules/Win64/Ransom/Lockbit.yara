rule Ransom_Win64_Lockbit_IDA_2147840143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbit.IDA!MTB"
        threat_id = "2147840143"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!!-Restore-My-Files-!!!.txt" wide //weight: 1
        $x_1_2 = "C:\\Work\\conti_v" ascii //weight: 1
        $x_1_3 = "hsfjuukjzloqu28oajh727190" ascii //weight: 1
        $x_1_4 = "CONTI_LOG.txt" wide //weight: 1
        $x_1_5 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy where \"ID='%s'\" delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Lockbit_AC_2147845572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbit.AC!MTB"
        threat_id = "2147845572"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 88 4c 3c 41 48 ff c7 48 83 ff 16 72}  //weight: 1, accuracy: High
        $x_1_2 = {f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 42 88 4c 05 b8 49 ff c0 49 83 f8 0d 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win64_Lockbit_BMC_2147898781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbit.BMC!MTB"
        threat_id = "2147898781"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "paste note after directory change and encryption yes" ascii //weight: 1
        $x_1_2 = "kill loop for taskmgr, cmd, regedit, powershell yes/no" ascii //weight: 1
        $x_1_3 = "reboot after end encryption of all files or disks yes/no" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Lockbit_XZ_2147904533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbit.XZ!MTB"
        threat_id = "2147904533"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 be 02 00 00 00 4c 8b 40 18 b8 56 55 55 55 c7 45 10 b2 88 1d 00 8b 4d 10 f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Lockbit_AUJ_2147932417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbit.AUJ!MTB"
        threat_id = "2147932417"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 89 05 da b3 00 00 48 8b 40 18 48 8b 78 20 48 8b 07 48 8b 18 48 8d b4 24 e0 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Lockbit_PMK_2147932644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbit.PMK!MTB"
        threat_id = "2147932644"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 ff c0 45 0f b6 c0 46 8a 8c 04 ?? ?? ?? ?? 44 00 ca 44 0f b6 d2 46 8a 9c 14 ?? ?? ?? ?? 46 88 9c 04 e0 03 00 00 46 88 8c 14 e0 03 00 00 46 02 8c 04 e0 03 00 00 45 0f b6 c9 46 8a 8c 0c ?? ?? ?? ?? 44 30 0c 01 48 ff c0 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Lockbit_ARAC_2147961296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbit.ARAC!MTB"
        threat_id = "2147961296"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b c1 48 2b c3 83 e0 1f 42 0f b6 04 00 32 01 32 c2 ?? ?? ?? ?? 48 ff c1 3b ?? 72 e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Lockbit_YBG_2147961404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbit.YBG!MTB"
        threat_id = "2147961404"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 c0 4d 69 c0 ?? ?? ?? ?? 89 c1 49 c1 e8 20 44 29 c1 d1 e9 44 01 c1 c1 e9 06 41 89 c8 41 c1 e0 07 41 29 c8 44 29 c0 88 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


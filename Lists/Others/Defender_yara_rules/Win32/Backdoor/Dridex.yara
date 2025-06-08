rule Backdoor_Win32_Dridex_2147708899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dridex"
        threat_id = "2147708899"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 65 72 00 75 00 33 32 2e 64 00 6e 65 6c 00 6c 6c 00 65 74 57 00 69 6e 64 6f 00 47 00 77 4c 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Dridex_2147708899_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dridex"
        threat_id = "2147708899"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ec e7 57 06 c7 45 ff c5 27 6e fb c7 45 03 c9 3c 83 63 c7 45 07 a9 74 0b cd e8 6f 23 03 00 4c 89 75 ef 41 8b fe 48 8d 4d d7 e8 4b 2d 03 00 48 8d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Dridex_SE_2147731694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dridex.SE!MTB"
        threat_id = "2147731694"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 0f af c6 8d 3c 40 8b ce 0f af cf 8b c7 99 2b c2 8b 55 10 03 ca d1 f8 03 c1 8b 4d 08 8a 0c 0b 32 c8 85 d2 74 0b 8b 55 08 88 0c 13 8b 55 10 eb 06 8b 4d 08 88 0c 0b}  //weight: 1, accuracy: High
        $x_1_2 = "\\bag\\FAST\\transactional\\unpleasa.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Dridex_SF_2147732014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dridex.SF!MTB"
        threat_id = "2147732014"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4e 38 8a 46 5c 30 04 11 42 3b 56 3c 72 f1 83 7e 44 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4e 40 8a 46 5c 30 04 11 42 3b 56 44 72 f1 8b 7e 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Dridex_AA_2147743877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dridex.AA!MSR"
        threat_id = "2147743877"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 3c 89 44 24 6c 8b 4c 24 68 ba 12 77 b0 0c 29 ca 89 54 24 60 8b 54 24 70 8b 74 24 74 81 c2 50 4a 69 26 83 d6 00 8b 7c 24 60 8a 5c 24 67 89 74 24 74 89 54 24 70 f7 d0 89 44 24 6c 8a 7c 24 4f 30 df 80 f7 d8 8b 44 24 74 8b 54 24 70 01 d2 11 c0 8b 74 24 48 89 44 24 38 8b 44 24 54 8a 1c 06 81 f1 ec 13 94 46 89 54 24 70 8b 54 24 38 89 54 24 74 00 fb 88 5c 24 5b 8b 54 24 44 01 c2 89 54 24 5c 39 f9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Dridex_AB_2147788369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dridex.AB!MTB"
        threat_id = "2147788369"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rpZmQ25Vm6" ascii //weight: 3
        $x_3_2 = "oKG3UkZg" ascii //weight: 3
        $x_3_3 = "2HSqtx9Uih" ascii //weight: 3
        $x_3_4 = "CLIPFORMAT_UserMarshal" ascii //weight: 3
        $x_3_5 = "CreatePropertySheetPageW" ascii //weight: 3
        $x_3_6 = "GetTempFileNameA" ascii //weight: 3
        $x_3_7 = "SHGetUnreadMailCountW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


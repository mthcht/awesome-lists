rule Trojan_Win64_Tedy_A_2147828733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.A!MTB"
        threat_id = "2147828733"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 44 39 65 06 74 39 48 03 fd 8b 47 fc 85 c0 74 21 44 8b 07 44 8b c8 8b 57 f8 4d 03 c7 49 03 d6 4c 89 64 24 20 48 8b cb ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GHN_2147845256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GHN!MTB"
        threat_id = "2147845256"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {45 89 f4 41 c0 fc 02 45 00 ec 83 c5 02 46 88 24 38 41 89 ef 0f b6 6c 24 67 40 80 fd 40 74 11 41 c0 e6 06 44 00 f5 4d 63 f7 41 ff c7 42 88 2c 30 45 31 ed e9}  //weight: 10, accuracy: High
        $x_1_2 = "NTI3NTZlNDE3Mw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_FG_2147848041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.FG!MTB"
        threat_id = "2147848041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 84 24 a8 00 00 00 0f b6 84 04 98 04 00 00 8b 8c 24 10 01 00 00 c1 e1 03 48 8b 94 24 a0 04 00 00 48 d3 ea 48 8b ca 0f b6 c9 33 c1 48 63 8c 24 a8 00 00 00 88 84 0c a0 67 00 00 eb 87}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SPS_2147850797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SPS!MTB"
        threat_id = "2147850797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8d 8d 68 01 00 00 45 33 c0 b2 01 8b cb e8 ?? ?? ?? ?? ff c3 83 fb 24 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_QC_2147851552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.QC!MTB"
        threat_id = "2147851552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 44 8b d3 41 be bf e5 f1 78 48 8b 50 18 48 83 c2 10 48 8b 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SPK_2147852473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SPK!MTB"
        threat_id = "2147852473"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 11 84 24 c0 00 00 00 0f 11 44 24 50 f2 0f 10 05 ?? ?? ?? ?? f2 0f 11 84 24 f0 00 00 00 0f 10 05 ?? ?? ?? ?? 0f 11 8c 24 e0 00 00 00 0f 10 0d ?? ?? ?? ?? 0f 11 84 24 00 01 00 00 0f 10 05 ?? ?? ?? ?? 0f 11 8c 24 10 01 00 00 0f 11 84 24 20 01 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPB_2147891569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPB!MTB"
        threat_id = "2147891569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {49 89 d8 4c 89 f2 48 89 f9 48 83 c7 02 e8 7e ff ff ff 48 89 f0 31 d2 48 83 c6 01 48 f7 f5 41 0f b6 04 14 30 03 48 83 c3 01 49 39 f5 75 d2}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_PABC_2147892091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.PABC!MTB"
        threat_id = "2147892091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 68 59 00 66 4d c7 44 24 6c 53 54 5e 55 c7 44 24 70 4d 49 66 49 c7 44 24 74 43 49 4e 5f c7 44 24 78 57 09 08 66 c7 44 24 7c 54 4e 5e 56 c7 45 80 56 14 5e 56 66 c7 45 84 56 3a c7 45 c8 43 72 65 61 c7 45 cc 74 65 46 69 c7 45 d0 6c 65 4d 61 c7 45 d4 70 70 69 6e 66 c7 45 d8 67 41 c6 45 da 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NTD_2147895927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NTD!MTB"
        threat_id = "2147895927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 c3 48 03 c0 49 83 24 c4 00 33 c0 eb db 48 89 5c 24 ?? 48 89 6c 24 ?? 48 89 74 24 ?? 57 48 83 ec 20 bf ?? ?? ?? ?? 48 8d 1d 60 f5 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NTD_2147895927_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NTD!MTB"
        threat_id = "2147895927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 84 23 01 00 00 85 c9 75 4a c7 05 9f 9d 01 00 ?? ?? ?? ?? 48 8d 15 e0 f0 00 00 48 8d 0d a1 f0 00 00 e8 44 4a}  //weight: 5, accuracy: Low
        $x_1_2 = "://ftp.2qk.cn/HD1-2.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NTD_2147895927_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NTD!MTB"
        threat_id = "2147895927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pod paczke BlazingPack" ascii //weight: 1
        $x_1_2 = "bledna licencja lub jestes zjebany" ascii //weight: 1
        $x_1_3 = "villadentex.pl" ascii //weight: 1
        $x_1_4 = "Classes loaded succesfuly" ascii //weight: 1
        $x_1_5 = "pod paczke Lunar Client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_RB_2147897550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RB!MTB"
        threat_id = "2147897550"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 24 38 48 8d 6c 24 38 48 b8 ba 06 e2 3b 5d 04}  //weight: 1, accuracy: High
        $x_1_2 = "ibhchocjdb/kfapioijci/fjfkdpkdco/fjfkdpkdco/kbpchiokil.Egcgaefamc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_EM_2147898412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.EM!MTB"
        threat_id = "2147898412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {30 84 0d 18 05 00 00 48 ff c1 48 83 f9 25 72 ed}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e8 2e 62 00 00 44 8b cb 4c 8b c0 33 d2 48 8d 0d ?? ?? ?? ?? e8 aa e8 ff ff}  //weight: 3, accuracy: Low
        $x_3_2 = {e8 0a 31 00 00 e8 0d 31 00 00 48 8d 2d ?? ?? ?? ?? 48 8d 15 55 00 02 00 41 b8 00 10 00 00 48 89 e9}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {49 8b c0 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 2b c8 0f b6 44 0d ?? 4b 8d 0c 39 41 00 41 ?? 49 8b c0 48 f7 e1 48 c1 ea}  //weight: 3, accuracy: Low
        $x_1_2 = "runas" ascii //weight: 1
        $x_1_3 = "BackDoor.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {84 c0 0f 84 36 01 00 00 40 32 f6 40 88 74 24 ?? e8 d6 f9 ff ff 8a d8 8b 0d 8a dd 05 00 83 f9 01 0f 84 23 01 00 00 85 c9 75 4a c7 05 73 dd 05 00 01 00 00 00 48 8d 15 6c 75 03 00 48 8d 0d 15 75 03 00}  //weight: 3, accuracy: Low
        $x_1_2 = "ROSHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HusClass" ascii //weight: 1
        $x_1_2 = "Key doesnt exist !" ascii //weight: 1
        $x_1_3 = "TTRs Internal Slotted" ascii //weight: 1
        $x_1_4 = "WORK ONLY ON EAC" ascii //weight: 1
        $x_1_5 = "vvsk2nJWPd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 0d 8f 88 02 00 48 89 44 24 ?? 48 89 0b 48 8d 53 ?? 0f 57 c0 c6 44 24 ?? 01 48 8d 4c 24 ?? 0f 11 02 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {45 33 c9 4c 8d 44 24 ?? ba f4 01 00 00 48 8d 4c 24 ?? e8 f4 5b ff ff 48 8d 15 ed 6b 03 00 48 8d 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {41 ff c0 48 ff c2 48 83 c0 28 49 3b d1 7c e1 eb 19 49 63 c0 48 8d 0c 80 41 8b 44 ca ?? 41 8b 74 ca ?? 4a 8d 1c 38 4e 8d 24 28 41 8b 04 24 4c 8b ac 24 48 03 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = "exploitation d" ascii //weight: 1
        $x_1_3 = "EXPLOIT\\BINARY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 12 45 33 c0 41 8d 50 ?? 33 c9 48 8b 03 ff 15 d1 2f 00 00 e8 f8 06 00 00 48 8b d8 48 83 38 ?? 74 14 48 8b c8}  //weight: 5, accuracy: Low
        $x_1_2 = "Fix Fake Damage" ascii //weight: 1
        $x_1_3 = "CARLOS CHEAT" ascii //weight: 1
        $x_1_4 = "AARYAN V4X - Sniper Panel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NT_2147899511_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NT!MTB"
        threat_id = "2147899511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 0f 6f 4c 24 ?? 48 8d 54 24 ?? 48 8d 0d 97 68 02 00 48 89 74 24 ?? 48 89 74 24 ?? 0f 29 4c 24 ?? e8 33 75 00 00 0f b6 33 4c 89 e1 c6 03 00}  //weight: 3, accuracy: Low
        $x_2_2 = {80 3b 00 75 11 40 88 33 40 84 f6 75 09 4c 89 e9 e8 bf 75 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "Attempting to rename file name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_AMBE_2147903244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.AMBE!MTB"
        threat_id = "2147903244"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 05 48 8d 04 d2 48 c1 e0 02 48 2b c8 42 0f b6 04 21 88 04 1e 48 ff c6 48 83 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPAA_2147905958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPAA!MTB"
        threat_id = "2147905958"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 4c 14 56 31 c8 0f b6 d8 48 8d 44 24 2c}  //weight: 3, accuracy: High
        $x_1_2 = "de_xor" ascii //weight: 1
        $x_1_3 = "de_Rc4" ascii //weight: 1
        $x_1_4 = "de_Aes" ascii //weight: 1
        $x_1_5 = "de_AesRc4Xor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SGA_2147906771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SGA!MTB"
        threat_id = "2147906771"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegFlushKey" ascii //weight: 1
        $x_1_2 = "com.embarcadero.lsasse" wide //weight: 1
        $x_1_3 = "DLLFILE" wide //weight: 1
        $x_1_4 = "logd64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SMD_2147907280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SMD!MTB"
        threat_id = "2147907280"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 c1 fa 04 8b c2 c1 e8 ?? 03 d0 0f be c2 6b d0 31 0f b6 c1 ff c1 2a c2 04 39 41 30 40 ff 83 f9 04 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_HNA_2147908379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.HNA!MTB"
        threat_id = "2147908379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ff ff ff ff 48 8b b4 24 c0 04 00 00 48 8b 9c 24 b0 04 00 00 48 8b bc 24 a0 04 00 00 48 8b 8c 24 90 04 00 00 48 33 cc}  //weight: 1, accuracy: High
        $x_1_2 = {48 c7 44 24 30 00 00 00 00 4c 8b cf c7 44 24 28 00 00 00 00 45 33 c0 33 d2 48 89 74 24 20 48 8b cb}  //weight: 1, accuracy: High
        $x_1_3 = {4f 70 65 6e 50 72 6f 63 65 73 73 [0-4] 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 [0-4] 50 72 6f 63 65 73 73 33 32 4e 65 78 74 57 [0-4] 50 72 6f 63 65 73 73 33 32 46 69 72 73 74 57 [0-4] 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 [0-4] 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 [0-4] 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_RM_2147909344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RM!MTB"
        threat_id = "2147909344"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b d0 8b 42 fc d3 e8 49 89 51 08 41 89 41 18 0f b6 0a 83 e1 0f 4a 0f be 84 11 e8 d7 02 00 42 8a 8c 11 f8 d7 02 00 48 2b d0 8b 42 fc d3 e8 49 89 51 08 41 89 41 1c 0f b6 0a 83 e1 0f 4a 0f be 84 11 e8 d7 02 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 74 00 72 00 61 00 6e 00 73 00 6c 00 61 00 74 00 65 00 20 00 6d 00 61 00 73 00 74 00 65 00 72 00 5c 00 [0-16] 57 00 72 00 61 00 70 00 70 00 65 00 72 00 5c 00 78 00 36 00 34 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 47 6f 6f 67 6c 65 20 74 72 61 6e 73 6c 61 74 65 20 6d 61 73 74 65 72 5c [0-16] 57 72 61 70 70 65 72 5c 78 36 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Tedy_RS_2147909972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RS!MTB"
        threat_id = "2147909972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 84 24 00 01 00 00 48 63 40 3c 48 8b 4c 24 48 48 03 c8 48 8b c1 48 63 4c 24 6c 48 6b c9 28 48 8d 84 08 08 01 00 00 48 89 84 24 98 00 00 00 48 8b 84 24 98 00 00 00 8b 40 14 48 8b 8c 24 98 00 00 00 8b 49 10 48 03 c1 48 89 84 24 c8 01 00 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATY_2147911512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATY!MTB"
        threat_id = "2147911512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 89 ca 41 8d 0c 18 42 32 4c 00 10 48 c1 fa 08 31 d1 4c 89 ca 49 c1 f9 18 48 c1 fa 10 31 d1 44 31 c9 42 88 4c 00 10 49 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATY_2147911512_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATY!MTB"
        threat_id = "2147911512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d6 48 89 55 97 41 b8 ?? ?? ?? ?? 4c 89 45 9f 88 55 87 c7 45 a7 ?? ?? ?? ?? b1 14 80 f1 55 48 8d 5b 01 49 3b d0 73 1f 48 8d 42 01 48 89 45 97 48 8d 45 87 49 83 f8 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATY_2147911512_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATY!MTB"
        threat_id = "2147911512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c8 05 88 43 40 48 85 d2 0f 84 54 01 00 00 48 83 7a 18 00 0f 84 39 01 00 00 48 8b 42 18 f0 83 00 01 48 8b 4b 30 48 85 c9 74 06 ff 15 c8 7d 01 00 4c 89 e9 e8 24 1d 00 00 48 8b 4b 28 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATY_2147911512_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATY!MTB"
        threat_id = "2147911512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 45 e0 88 85 f0 14 00 00 0f 28 45 c0 0f 28 4d d0 0f 29 8d e0 14 00 00 0f 29 85 d0 14 00 00 31 c9 31 d2 49 89 f8 ff 15 14 49 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b d7 4c 8b 4d c7 4b 8b 8c cb 20 32 05 00 48 03 ca 8a 04 32 42 88 44 f9 3e ff c7 48 ff c2 48 63 c7}  //weight: 1, accuracy: High
        $x_1_3 = {49 2b f6 4b 8b 8c eb 20 32 05 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPBX_2147912805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPBX!MTB"
        threat_id = "2147912805"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /IM ProcessHacker.exe /F" ascii //weight: 1
        $x_1_2 = "taskkill /IM dnSpy.exe /F" ascii //weight: 1
        $x_1_3 = "taskkill /IM cheatengine-x86_64.exe /F" ascii //weight: 1
        $x_1_4 = "taskkill /IM ollydbg.exe /F" ascii //weight: 1
        $x_1_5 = "taskkill /IM ida64.exe /F" ascii //weight: 1
        $x_1_6 = "taskkill /IM x64dbg.exe /F" ascii //weight: 1
        $x_1_7 = "Stop debugging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATE_2147912968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATE!MTB"
        threat_id = "2147912968"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 08 49 83 c0 01 31 d9 c1 eb 08 0f b6 c9 33 1c 8a 4c 39 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ZQ_2147913604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ZQ!MTB"
        threat_id = "2147913604"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 33 ?? 31 f8 88 44 33 ?? 48 89 fa 48 c1 fa ?? 31 d0 48 89 fa 48 c1 fa ?? 31 d0 48 89 fa 48 83 c7 ?? 48 c1 fa ?? 31 d0 88 44 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ZW_2147913634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ZW!MTB"
        threat_id = "2147913634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 6f e2 66 0f 61 d3 66 41 0f db c8 66 0f 69 e3 66 0f 61 d4 66 41 0f db d0 66 0f 67 ca 66 0f ef c8 0f 11}  //weight: 1, accuracy: High
        $x_1_2 = {41 32 54 04 ?? 49 c1 f9 ?? 31 ca 48 c1 f9 ?? 44 31 ca 31 ca 41 88 54 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ZX_2147913649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ZX!MTB"
        threat_id = "2147913649"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 54 03 10 48 c1 f9 10 31 f2 31 ca 48 89 f1 48 c1 f9 18 31 ca 48 8d 4e 01 88 54 03 10}  //weight: 1, accuracy: High
        $x_1_2 = "static/loader_client_no_literals_compression.bin" ascii //weight: 1
        $x_1_3 = "dXNlcjpRd2VydHkxMjMh" ascii //weight: 1
        $x_1_4 = "updater.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_DA_2147914003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.DA!MTB"
        threat_id = "2147914003"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 48 8d 0d ?? ?? ?? ?? 48 8b 54 24 08 0f b6 0c 11 2b c1 05 00 01 00 00 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 48 8b 0c 24 48 8b 54 24 28 48 03 d1 48 8b ca 88 01 48 8b 44 24 08 48 ff c0 33 d2 b9 08 00 00 00 48 f7 f1 48 8b c2 48 89 44 24 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_DA_2147914003_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.DA!MTB"
        threat_id = "2147914003"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\\\.\\VBoxMiniRdrDN" ascii //weight: 10
        $x_10_2 = "FortniteClient-Win64-Shipping.exe" ascii //weight: 10
        $x_1_3 = "D3D11CreateDeviceAndSwapChain" ascii //weight: 1
        $x_1_4 = "d3d11.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GP_2147914911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GP!MTB"
        threat_id = "2147914911"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 41 aa 30 44 0d a8 48 ff c1 48 83 f9 30 72 f0 c6 45 d9 00 4c 89 7c 24 48 4c 89 7c 24 58 48 c7 44 24 60 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPJ_2147914912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPJ!MTB"
        threat_id = "2147914912"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "cdn.discordapp.com/attachments/1223133498550911067/1231358676225359932/svhost.exe" ascii //weight: 5
        $x_1_2 = "cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_3 = "ces.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_MD_2147915202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.MD!MTB"
        threat_id = "2147915202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TestMalvare.pdb" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "DisableRealtimeMonitoring" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NAA_2147915616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NAA!MTB"
        threat_id = "2147915616"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Musquitao\\Desktop\\BR_2023\\LOAD_2023\\DLL-CPP\\D\\x64\\Release\\D.pdb" ascii //weight: 5
        $x_1_2 = "\\Documents" ascii //weight: 1
        $x_1_3 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_4 = "D.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_RF_2147916602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RF!MTB"
        threat_id = "2147916602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 73 01 0f 1f 40 00 0f 1f 84 00 00 00 00 00 49 8b 14 de 49 8b c5 66 0f 1f 84 00 00 00 00 00 0f b6 0c 02 48 ff c0 41 3a 4c 04 ff 75 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_DKZ_2147920721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.DKZ!MTB"
        threat_id = "2147920721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 50 4f 30 14 08 48 ff c0 48 83 f8 03 72 f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_C_2147922679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.C!MTB"
        threat_id = "2147922679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ollydbg.exe" ascii //weight: 2
        $x_2_2 = "x64dbg.exe" ascii //weight: 2
        $x_2_3 = "x32dbg.exe" ascii //weight: 2
        $x_2_4 = "Process Hacker 2" ascii //weight: 2
        $x_2_5 = "Wireshark" ascii //weight: 2
        $x_3_6 = "@FACK YOU Donkey." ascii //weight: 3
        $x_3_7 = "netsh advfirewall firewall delete rule name" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Tedy_RZ_2147922688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.RZ!MTB"
        threat_id = "2147922688"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "start cmd /C \"color b && title Error && echo" ascii //weight: 1
        $x_1_2 = "certutil -hashfile" ascii //weight: 1
        $x_1_3 = "&& timeout /t 5" ascii //weight: 1
        $x_1_4 = "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" ascii //weight: 1
        $x_2_5 = {8d 50 7f 30 14 08 48 ff c0 48 83 f8 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARA_2147923215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARA!MTB"
        threat_id = "2147923215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 54 45 40 48 8b 85 ?? ?? ?? ?? 66 89 94 45 f0 02 00 00 48 83 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARA_2147923215_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARA!MTB"
        threat_id = "2147923215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 48 8b 4d 10 48 8b 55 f8 48 01 ca 32 45 f7 88 02 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 72 d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARA_2147923215_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARA!MTB"
        threat_id = "2147923215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "curl -F \"image=@" ascii //weight: 2
        $x_2_2 = "\\Microsoft\\Windows\\.winSession" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARA_2147923215_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARA!MTB"
        threat_id = "2147923215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Startup\\NVIDIAGraphics.lnk" ascii //weight: 2
        $x_2_2 = "\\Startup\\MicrosoftDefender.lnk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARA_2147923215_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARA!MTB"
        threat_id = "2147923215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true" ascii //weight: 1
        $x_1_2 = "-DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true" ascii //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GA_2147924836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GA!MTB"
        threat_id = "2147924836"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "eJuVBxglqjBknVHYaYdaupucmUyKFLeJuVBxglqjBknVHYaYdaupucmUyKFL" ascii //weight: 8
        $x_1_2 = "GetFullPathNameW" ascii //weight: 1
        $x_1_3 = "GetTempFileNameW" ascii //weight: 1
        $x_1_4 = "InitializeSecurityDescriptor" ascii //weight: 1
        $x_1_5 = "CryptCATAdminCalcHashFromFileHandle" ascii //weight: 1
        $x_1_6 = "SetEndOfFile" ascii //weight: 1
        $x_1_7 = "UnknownProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Tedy_GNZ_2147925762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GNZ!MTB"
        threat_id = "2147925762"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ed 30 e6 33 6a ?? 24 ?? a8 ?? 53 52 01 ba ?? ?? ?? ?? 01 54 f5}  //weight: 5, accuracy: Low
        $x_5_2 = {01 c7 31 04 34 a3 ?? ?? ?? ?? ?? ?? ?? ?? 2b 11 2e 9d c8 67 03 ?? 08 e6 13 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NM_2147925901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NM!MTB"
        threat_id = "2147925901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e8 f1 03 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 02 00 00 00 48 89 d9 ba 00 00 00 40 41 b8 02 00 00 00 45 31 c9}  //weight: 2, accuracy: High
        $x_1_2 = {48 81 ff 00 80 00 00 41 bc 00 80 00 00 4c 0f 42 e7 4c 89 f1 4c 89 e2 e8 d4 0c 00 00 c7 44 24 70 00 00 00 00 48 c7 44 24 20 00 00 00 00 4c 89 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_BSA_2147926353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.BSA!MTB"
        threat_id = "2147926353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CuzPP.exe" ascii //weight: 10
        $x_1_2 = "GoonEye.exe" ascii //weight: 1
        $x_1_3 = "\\Release\\CuzPP.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPK_2147927072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPK!MTB"
        threat_id = "2147927072"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Imgui-Blue-loader-master\\Imgui-Blue-loader-master\\ImGui\\imstb_textedit.h" ascii //weight: 3
        $x_2_2 = "blue_loader_imgui" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_AST_2147927312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.AST!MTB"
        threat_id = "2147927312"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {30 41 c2 04 84 91 f9 44 09 dd 3e 54 7b 34 18 12 07 0a ed 19 d4 10 f6 13 cc}  //weight: 5, accuracy: High
        $x_5_2 = {32 38 30 04 ee 84 98 ?? ?? ?? ?? 22 0f 32 52 db}  //weight: 5, accuracy: Low
        $x_5_3 = {58 53 51 52 56 57 55 48 89 c3 48 83 eb 05 b9 58 60 ea 00 48 29 cb 50 b8 54 4b 44 00 48 01 d8}  //weight: 5, accuracy: High
        $x_5_4 = {40 43 2b 20 e4 06 31 93 e8 83 b5 c1 88 0b 15 d0 84 3f 54 01 06 80 52 83 10 23 f8 1c 08 a6 3a 20 0c 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Tedy_ASU_2147927476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ASU!MTB"
        threat_id = "2147927476"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5e f6 66 24 80 b1 ?? ?? ?? ?? 9a c8 b9 4e a2 68 0d 41 29 3c 24 b3 05 f2 b2 8e d7 35 14 0f 87 de 53 71}  //weight: 5, accuracy: Low
        $x_5_2 = {bb f0 27 ba ff f3 0c b5 30 cc ec ed 5c 80 31 e7}  //weight: 5, accuracy: High
        $x_5_3 = {64 25 12 a4 6c 35 bc cb ea b9 c9 2d 17 23 6d 7f 97 34 b6 e2 3e}  //weight: 5, accuracy: High
        $x_5_4 = {33 29 89 24 74 20 c3 45 2b ed}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Tedy_GB_2147928064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GB!MTB"
        threat_id = "2147928064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 48 8b 4d 10 48 8b 55 f8 48 01 ca 32 45 20 88 02 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 72 d3}  //weight: 1, accuracy: High
        $x_1_2 = "run_exe_from_memory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NIT_2147928292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NIT!MTB"
        threat_id = "2147928292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 74 24 30 eb 0f 44 8b 63 10 4d 03 e6 49 8b f4 4c 89 64 24 30 4c 89 64 24 28 49 8b 04 24 48 85 c0 74 3a 48 b9 00 00 00 00 00 00 00 80 48 85 c1 49 8b cf 0f b7 d0 75 05 4a 8d 54 30 02 ff 15 ca 9e 17 00 48 89 06 48 85 c0 75 08 33 ff 89 7c 24 20 eb 0e 49 83 c4 08 48 83 c6 08 eb a2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GE_2147928375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GE!MTB"
        threat_id = "2147928375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c1 32 02 32 44 0d ff 34 82 88 44 0d ff 48 ff c1 48 83 f9 0e 72 e8}  //weight: 1, accuracy: High
        $x_1_2 = "DllInstall" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GF_2147928616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GF!MTB"
        threat_id = "2147928616"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 33 08 0f b6 40 08 34 1a 48 89 4c 24 50 88 44 24 58 48 8d 4c 24 30 48 8d 54 24 50 41 b8 09 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "execute_python_entrypoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GCM_2147928681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GCM!MTB"
        threat_id = "2147928681"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 00 88 45 f6 80 75 f6 aa 48 8b 45 f8 28 45 f6 0f b6 45 f7 30 45 f6 0f b6 45 f6 c1 e0 04 89 c2 0f b6 45 f6 c0 e8 04 09 d0 88 45 f6 f6 55 f6 0f b6 5d f6 48 8b 45 f8 48 89 c2 48 8b 4d 20 e8 28 80}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ARAZ_2147929327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ARAZ!MTB"
        threat_id = "2147929327"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 4c 24 58 4c 89 e2 8d 44 00 02 48 89 5c 24 20 41 b9 01 00 00 00 89 44 24 28 ff 15 ec ef 0e 00}  //weight: 2, accuracy: High
        $x_2_2 = {48 83 c1 01 0f b6 04 10 41 30 01 48 39 cb 75 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Tedy_GTR_2147930031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GTR!MTB"
        threat_id = "2147930031"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d0 34 b6 39 e3 58 6c 18 22}  //weight: 5, accuracy: High
        $x_5_2 = {9c ec 28 76 ?? a4 32 44 3a ?? 55 1a 8b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_NOP_2147930766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.NOP!MTB"
        threat_id = "2147930766"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c0 07 31 d2 49 f7 f1 41 8a 04 10 48 8b 14 24 30 04 11 48 8b 44 24 ?? 48 83 c0 05 31 d2 49 f7 f1 48 89 54 24 20 48 8b 04 24 48 ff c0 48 89 44 24 ?? 8b 05 e3 63 68 00 8d 50}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_PYZ_2147933401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.PYZ!MTB"
        threat_id = "2147933401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b8 9d 82 97 53 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 31 41 0f b6 c0 2a c1 04 33 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 21 7c d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_SPD_2147935383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.SPD!MTB"
        threat_id = "2147935383"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 85 c9 0f 84 ?? 00 00 00 48 8b 83 00 00 00 00 4c 31 e8 48 89 83 00 00 00 00 48 ff c9 [0-50] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GVA_2147935955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GVA!MTB"
        threat_id = "2147935955"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 30 44 0e 0b 41 02 44 0e 0b e2 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_AB_2147936820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.AB!MTB"
        threat_id = "2147936820"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 89 c3 41 81 f3 ff ff ff ff 41 81 e3 14 d1 28 6f 41 81 e1 ff ff ff ff 44 09 d2 45 09 cb 44 31 da 83 f2 ff 41 89 c1 41 31 d1 41 21 c1 89 c2 83 f2 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GPP_2147938483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GPP!MTB"
        threat_id = "2147938483"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "source\\repos\\CVE-2024-20656\\Expl\\x64\\Release" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_PGT_2147939099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.PGT!MTB"
        threat_id = "2147939099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 79 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 41 00 70 00 70}  //weight: 1, accuracy: High
        $x_4_2 = {30 01 48 8d 49 01 48 83 eb 01 75 f4}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_PGT_2147939099_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.PGT!MTB"
        threat_id = "2147939099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 33 c4 48 89 84 24 a0 03 00 00 48 8b da 4c 8b f1 48 89 94 24 c0 00 00 00 45 33 ff 44 89 7c 24 30 0f 57 c0 0f 11 02 4c 89 7a 10 4c 89 7a 18 41 b8 0f 05 00 00 48 8d 15 ?? ?? ?? 00 48 8b cb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_AD_2147939495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.AD!MTB"
        threat_id = "2147939495"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 57 c0 33 c0 0f 11 45 a0 0f 11 45 b0 0f 11 45 c0 0f 11 45 d0 0f 11 45 e0 0f 11 45 f0 0f 11 45 00 4c 89 6d a0 0f 11 45 a8 4c 89 6d b8 48 c7 45 c0 0f 00 00 00 88 45 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_AH_2147939502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.AH!MTB"
        threat_id = "2147939502"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 db 48 8b 54 24 58 48 83 fa 07 0f 86 c1 00 00 00 48 8b 4c 24 40 48 8d 14 55 02 00 00 00 48 8b c1 48 81 fa 00 10 00 00 0f 82 9f 00 00 00 48 8b 49 f8}  //weight: 1, accuracy: High
        $x_1_2 = "Vixen.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_WIV_2147939599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.WIV!MTB"
        threat_id = "2147939599"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 2b c6 41 8b c0 c1 e8 18 32 c1 88 85 ?? 02 00 00 41 8b c0 c1 e8 10 32 c1 88 85 ?? 02 00 00 41 8b c0 c1 e8 08 32 c1 88 85 ?? 02 00 00 44 32 c1 44 88 85 43 02 00 00 33 c0 0f 57 c9 f3 0f 7f 8d 50 02 00 00 48 89 85 60 02 00 00 88 4c 24 50 4c 8d 44 24 50 33 d2 48 8d 8d 50 02 00 00 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATYE_2147939644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATYE!MTB"
        threat_id = "2147939644"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 03 40 32 c6 88 44 24 30 48 3b bd ?? ?? ?? ?? 74 0e 88 07 48 ff c7 48 89 bd ?? ?? ?? ?? eb 1b 4c 8d 44 24 30 48 8b d7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ATD_2147939770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ATD!MTB"
        threat_id = "2147939770"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 57 c0 0f 11 45 c8 48 89 45 d8 48 8d 95 a0 03 00 00 48 83 bd b8 03 00 00 0f 48 0f 47 95 a0 03 00 00 48 8d 45 c8 48 89 44 24 48 48 8d 85 20 04 00 00 48 89 44 24 40 4c 89 6c 24 38 4c 89 6c 24 30 44 89 6c 24 28 44 89 6c 24 20 45 33 c9 45 33 c0 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_2_2 = {48 8d 45 27 48 89 75 27 48 89 44 24 50 48 8d 4d 37 89 74 24 48 45 33 c9 89 74 24 40 45 33 c0 89 74 24 38 b2 01 89 74 24 30 89 74 24 28 89 74 24 20 89 75 37 66 c7 45 3b 00 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_WL_2147940255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.WL!MTB"
        threat_id = "2147940255"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 40 10 48 89 05 9f 0d 01 00 31 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_STAE_2147940713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.STAE!MTB"
        threat_id = "2147940713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 75 a7 48 8d 1d ba bb 00 00 0f 57 c0 0f 11 45 af 8b d6 48 89 55 bf 41 b8 0f 00 00 00 4c 89 45 c7 88 55 af c7 45 a7 01 00 00 00 b1 3e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_STAO_2147940714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.STAO!MTB"
        threat_id = "2147940714"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 81 ec e0 06 00 00 0f 29 70 c8 0f 29 78 b8 44 0f 29 40 a8 44 0f 29 48 98 48 8b 05 01 c5 00 00 48 33 c4 48 89 85 90 05 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_PGL_2147940784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.PGL!MTB"
        threat_id = "2147940784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 44 24 50 48 3b c5 7d 17 48 05 ?? ?? ?? ?? 48 8d 4c 24 40 48 89 44 24 40}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_KK_2147943868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.KK!MTB"
        threat_id = "2147943868"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 5d e0 48 89 5c 24 50 48 89 5c 24 48 48 89 5c 24 40 48 89 5c 24 38 89 5c 24 30 4c 89 74 24 28 4c 89 7c 24 20 4c 8b ce 45 33 c0 ba ff ff 1f 00 48 8d 4d e0 ff}  //weight: 5, accuracy: High
        $x_3_2 = "chrome_decrypt_cookies.txt" ascii //weight: 3
        $x_2_3 = "chrome_decrypt_payments.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GVD_2147944553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GVD!MTB"
        threat_id = "2147944553"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {0f b6 45 de 83 e0 01 88 45 f6 83 7d f8 00 7e 1a 0f b6 45 f7 32 45 f6 0f b6 c0 0f b6 55 df 83 e2 01 39 d0 74 4f}  //weight: 30, accuracy: High
        $x_2_2 = "**User:** %s\\n**Computer:** %s\\n**IP:** %s" ascii //weight: 2
        $x_3_3 = "\\Google\\Chrome\\User Data" wide //weight: 3
        $x_3_4 = "\\Microsoft\\Edge\\User Data" wide //weight: 3
        $x_3_5 = "\\Yandex\\YandexBrowser\\User Data" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_30_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Tedy_AK_2147945011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.AK!MTB"
        threat_id = "2147945011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 33 c4 8b f8 0f 57 c0 0f 11 03 48 89 73 10 48 c7 43 18 0f 00 00 00 c6 03 00 c7 44 24 20 01 00 00 00 4c 8b 6c 24 48 4c 8b 7c 24 30 83 f8 0f 74 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_TMX_2147945109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.TMX!MTB"
        threat_id = "2147945109"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 c0 10 31 d2 48 3b 95 f0 02 00 00 48 8d 95 f8 02 00 00 48 0f 41 ca 4c 8b 09 48 8d 8d}  //weight: 1, accuracy: High
        $x_1_2 = "pintest.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_GVB_2147946061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.GVB!MTB"
        threat_id = "2147946061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 75 72 6c 20 2d 2d 73 69 6c 65 6e 74 20 68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f [0-16] 20 2d 2d 6f 75 74 70 75 74 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-16] 20 3e 6e 75 6c 20 32 3e 26 31}  //weight: 2, accuracy: Low
        $x_1_2 = {63 64 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 20 26 26 20 [0-16] 2e 65 78 65 20 [0-16] 2e 73 79 73 20 3e 6e 75 6c 20 32 3e 26 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tedy_ZXU_2147946135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tedy.ZXU!MTB"
        threat_id = "2147946135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "! fud cat shit also fuck niggers frfrfr." ascii //weight: 6
        $x_5_2 = "0XYZAXAY" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win64_LockBit_B_2147919370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.B"
        threat_id = "2147919370"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1.!T" ascii //weight: 1
        $x_1_2 = {99 b5 5b 9b}  //weight: 1, accuracy: High
        $x_1_3 = {09 a6 52 d2}  //weight: 1, accuracy: High
        $x_1_4 = {cc bf 63 aa}  //weight: 1, accuracy: High
        $x_1_5 = {1d aa a3 3c}  //weight: 1, accuracy: High
        $x_1_6 = {5b 8d 47 89}  //weight: 1, accuracy: High
        $x_1_7 = {c5 0f 95 bc}  //weight: 1, accuracy: High
        $x_1_8 = {23 32 a1 6f}  //weight: 1, accuracy: High
        $x_1_9 = "XpSimulateParanoid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockBit_NB_2147920141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.NB!MTB"
        threat_id = "2147920141"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b ca 83 e1 7f 0f b6 0c 39 0f b6 84 14 ?? ?? 00 00 32 c8 88 8c 14 ?? ?? 00 00 48 ff c2 48 83 fa}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockBit_PH_2147929528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.PH!MTB"
        threat_id = "2147929528"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 ?? 48 63 54 24 ?? 44 0f b7 04 ?? 8b 44 24 ?? 41 b9 [0-4] 99 41 f7 f9 83 c2 ?? 41 31 d0 48 63 44 24 ?? 66 44 89 ?? ?? 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockBit_M_2147929542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.M"
        threat_id = "2147929542"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 08 32 4c 04 20 88 0b 48 ff c0 eb e2}  //weight: 1, accuracy: High
        $x_1_2 = {44 0f b6 ca 45 69 c9 01 01 01 ?? 49 83 f8 07 76 0d}  //weight: 1, accuracy: Low
        $n_1_3 = "[%d] Decrypted:" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win64_LockBit_AYA_2147929767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.AYA!MTB"
        threat_id = "2147929767"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YOUR FILES HAVE BEEN ENCRYPTED! Send 5 BTC to unlock." ascii //weight: 3
        $x_1_2 = "RANSOM_NOTE.txt" ascii //weight: 1
        $x_1_3 = "net user TrojanUser" ascii //weight: 1
        $x_1_4 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
        $x_1_6 = "DisableRegistryTools" ascii //weight: 1
        $x_1_7 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_8 = "bcdedit /delete {bootmgr} /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


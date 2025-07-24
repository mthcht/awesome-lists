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

rule Ransom_Win64_LockBit_YAC_2147934874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.YAC!MTB"
        threat_id = "2147934874"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "data are stolen and encrypted" ascii //weight: 10
        $x_1_2 = "LockBit 3.0 " ascii //weight: 1
        $x_1_3 = "world's fastest ransomware" ascii //weight: 1
        $x_1_4 = "data will be published on TOR website" ascii //weight: 1
        $x_1_5 = "do not pay the ransom" ascii //weight: 1
        $x_1_6 = " delete your data " ascii //weight: 1
        $x_1_7 = "decrypt one file for free" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockBit_GVA_2147934998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.GVA!MTB"
        threat_id = "2147934998"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".xlock" ascii //weight: 1
        $x_3_2 = "LockBit 3.0 the world's fastest ransomware since 2019" ascii //weight: 3
        $x_1_3 = "Your data are stolen and encrypted" ascii //weight: 1
        $x_1_4 = "The data will be published on TOR website if you do not pay the ransom " ascii //weight: 1
        $x_1_5 = "You need contact us and decrypt one file for free" ascii //weight: 1
        $x_1_6 = "You can contact us in email or qtox." ascii //weight: 1
        $x_1_7 = "Warning! Do not DELETE or MODIFY any files, it can lead to recovery problems!" ascii //weight: 1
        $x_1_8 = "Would you like to earn millions of dollars $$$ ?" ascii //weight: 1
        $x_1_9 = "main.traverseAndEncryptDisk" ascii //weight: 1
        $x_1_10 = "main.loadRSAPublicKeyFromPEM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockBit_AQUA_2147941881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.AQUA!MTB"
        threat_id = "2147941881"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-----BEGIN RSA PUBLIC KEY-----" ascii //weight: 1
        $x_1_2 = "-----END RSA PUBLIC KEY-----" ascii //weight: 1
        $x_3_3 = "\\work\\tools\\ai\\ak47\\cpp\\encrypt\\encrypt\\x64\\Release\\encrypt.pdb" ascii //weight: 3
        $x_1_4 = "GetLogicalDrives" ascii //weight: 1
        $x_1_5 = "How to decrypt my data.txt" ascii //weight: 1
        $x_1_6 = "decryptiondescription.pdf" ascii //weight: 1
        $x_3_7 = "Important!!!.pdf" ascii //weight: 3
        $x_1_8 = ".lock" ascii //weight: 1
        $x_1_9 = "How to decrypt my data.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockBit_MKC_2147947169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.MKC!MTB"
        threat_id = "2147947169"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-----BEGIN RSA PUBLIC KEY-----" ascii //weight: 1
        $x_1_2 = "-----END RSA PUBLIC KEY-----" ascii //weight: 1
        $x_3_3 = "hijacked.pdb" ascii //weight: 3
        $x_1_4 = "decryptiondescription.pdf" ascii //weight: 1
        $x_2_5 = ".lock" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockBit_TRX_2147947397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.TRX!MTB"
        threat_id = "2147947397"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "How to decrypt my data.txt" ascii //weight: 1
        $x_1_2 = "Your decrypt ID:" ascii //weight: 1
        $x_1_3 = "@proton.me" ascii //weight: 1
        $x_2_4 = "ai\\ak47\\writenull\\x64\\Release\\writenull.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


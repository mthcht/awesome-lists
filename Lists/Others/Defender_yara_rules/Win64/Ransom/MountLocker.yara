rule Ransom_Win64_MountLocker_A_2147780025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MountLocker.A"
        threat_id = "2147780025"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MountLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b df 48 8b d7 48 85 c9 74 ?? 4c 8b c1 4c 2b c7 8a 02 41 88 04 10 49 03 d6 49 2b de 75 ?? 49 03 cf 48 8d 1d ?? ?? ?? ?? 33 d2 0f b6 44 15 97 48 c1 e8 04 8a 84 18 ?? ?? ?? ?? 88 01 49 03 ce 0f b6 44 15 97 49 03 d6 83 e0 0f 8a 84 18 ?? ?? ?? ?? 88 01 49 03 ce 48 83 fa 10 72 ?? 48 8b ?? ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "%CLIENT_ID%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MountLocker_A_2147809905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MountLocker.A!MTB"
        threat_id = "2147809905"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MountLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ChaCha20" ascii //weight: 3
        $x_3_2 = "CRYPTOGAMS" ascii //weight: 3
        $x_3_3 = "CLIENT_ID" ascii //weight: 3
        $x_3_4 = "attrib -s -r -h" ascii //weight: 3
        $x_3_5 = "bootmgr" ascii //weight: 3
        $x_3_6 = "cmd.exe /c start" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MountLocker_RPR_2147809922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MountLocker.RPR!MTB"
        threat_id = "2147809922"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MountLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Quantum Locker" ascii //weight: 1
        $x_1_2 = ".onion" ascii //weight: 1
        $x_1_3 = "README_TO_DECRYPT" wide //weight: 1
        $x_1_4 = "locker_64" ascii //weight: 1
        $x_1_5 = "CryptEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MountLocker_PA_2147959496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MountLocker.PA!MTB"
        threat_id = "2147959496"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MountLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecoveryManual.html" wide //weight: 1
        $x_1_2 = "YOUR NETWORK HAS BEEN HACKED" ascii //weight: 1
        $x_2_3 = "[INFO] locker > start init script" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


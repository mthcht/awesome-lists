rule Ransom_Win32_QuantumLocker_MAK_2147811530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/QuantumLocker.MAK!MTB"
        threat_id = "2147811530"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "QuantumLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "expand 32-byte k" ascii //weight: 1
        $x_1_2 = "%CLIENT_ID%" ascii //weight: 1
        $x_1_3 = "Files on the workstations in your network were encrypted" ascii //weight: 1
        $x_1_4 = "After a payment you'll get network decryption" ascii //weight: 1
        $x_1_5 = ".onion/?cid=%CLIENT_ID%" ascii //weight: 1
        $x_1_6 = "Quantum Locker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_QuantumLocker_AB_2147820457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/QuantumLocker.AB"
        threat_id = "2147820457"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "QuantumLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {66 8b 45 fc 66 83 c0 01 66 89 45 fc 0f b7 45 fc 0f b7 4d f8 3b c1 7d 29 ff 75 f4 e8 ?? ?? ?? ?? 59 89 45 f4 0f b7 45 fc 8b 4d 08 0f b6 04 01 0f b6 4d f4 33 c1 0f b7 4d fc 8b 55 0c 88 04 0a eb bf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_QuantumLocker_PC_2147831587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/QuantumLocker.PC!MTB"
        threat_id = "2147831587"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "QuantumLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 45 fc 0f b7 4d f8 3b c1 7d 29 ff 75 f4 e8 ?? ?? ?? ?? 59 89 45 f4 0f b7 45 fc 8b 4d 08 0f b6 04 01 0f b6 4d f4 33 c1 0f b7 4d fc 8b 55 0c 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


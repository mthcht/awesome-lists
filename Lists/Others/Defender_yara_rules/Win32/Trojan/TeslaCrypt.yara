rule Trojan_Win32_TeslaCrypt_DA_2147819397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeslaCrypt.DA!MTB"
        threat_id = "2147819397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 84 24 24 01 00 00 89 8c 24 14 01 00 00 8a 9c 24 3d 01 00 00 8b 8c 24 14 01 00 00 32 9c 24 3d 01 00 00 88 9c 24 3d 01 00 00 39 c8 0f 83}  //weight: 2, accuracy: High
        $x_2_2 = {8a 44 24 4a 8a 4c 24 6c 30 c8 8b 54 24 10 f7 d2 8b 74 24 14 f7 d6 89 74 24 78 89 54 24 7c 24 01 88 44 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TeslaCrypt_GHC_2147843803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeslaCrypt.GHC!MTB"
        threat_id = "2147843803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecoveryManual.html" ascii //weight: 1
        $x_1_2 = "readme.txt" ascii //weight: 1
        $x_1_3 = "bhv.encryption.encrypt_files" ascii //weight: 1
        $x_1_4 = "bhv.ransom.ransom_note" ascii //weight: 1
        $x_1_5 = "Error checking for ransomware files" ascii //weight: 1
        $x_1_6 = "Unable to get SeDebugPrivileges, may be unable to clean up child processes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_TeslaCrypt_ARAX_2147931744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeslaCrypt.ARAX!MTB"
        threat_id = "2147931744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 0c c5 00 00 00 00 c1 e8 1d 0b c1 a3 f0 e6 42 00 8a 0a 80 c9 20 80 c9 20 88 4d 0c 8b 4d 0c 81 e1 ff 00 00 00 33 c1 42 a3 f0 e6 42 00 89 15 f4 e6 42 00 80 3a 00 75 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TeslaCrypt_ARA_2147944005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeslaCrypt.ARA!MTB"
        threat_id = "2147944005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0e 84 c9 74 15 32 4d ff 8b 45 08 2a ca fe c9 88 0c 33 42 46 3b d7 72 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TeslaCrypt_ARAC_2147949269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeslaCrypt.ARAC!MTB"
        threat_id = "2147949269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 0c c5 00 00 00 00 c1 e8 1d 0b c1 a3 ?? ?? ?? ?? 8a 0a 80 c9 20 80 c9 20 88 4d 0c 8b 4d 0c 81 e1 ff 00 00 00 33 c1 42 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 80 3a 00 75 c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TeslaCrypt_AB_2147955224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeslaCrypt.AB!MTB"
        threat_id = "2147955224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8b 4c 24 10 66 8b 14 41 66 89 d6 66 83 ?? ?? 66 89 d7 66 83 c7 ?? 66 83 fe ?? 66 0f 42 d7 8b 5c 24 30 66 39 14 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_FrostLizzard_C_2147925361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FrostLizzard.C!dha"
        threat_id = "2147925361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FrostLizzard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 8b 40 30 8b 4d e8 66 0f be 04 08 8b 4d e8 8b 55 b0 66 89 04 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FrostLizzard_D_2147925363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FrostLizzard.D!dha"
        threat_id = "2147925363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FrostLizzard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e0 8b 4d f0 8b 55 e0 8b 75 c4 66 8b 14 56 66 89 14 41 8b 45 e0 83 c0 01 89 45 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FrostLizzard_D_2147925363_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FrostLizzard.D!dha"
        threat_id = "2147925363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FrostLizzard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 14 24 8b 55 3c 01 ea 8b 4c ca 78 8b 5c 0d 20 01 eb 8b 54 0d 1c 89 54 24 08 8b 4c 0d 24 89 4c 24 10 31 d2 90 90 90 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


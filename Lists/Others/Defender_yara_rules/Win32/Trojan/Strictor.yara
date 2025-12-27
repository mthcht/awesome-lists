rule Trojan_Win32_Strictor_GMR_2147893059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strictor.GMR!MTB"
        threat_id = "2147893059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".vmp0" ascii //weight: 1
        $x_1_2 = "PFGydcB" ascii //weight: 1
        $x_1_3 = "Logon.exe" ascii //weight: 1
        $x_1_4 = "rxjhdlq.bak" ascii //weight: 1
        $x_1_5 = "XWuiqx" ascii //weight: 1
        $x_1_6 = "iwvRMHx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strictor_A_2147931777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strictor.A"
        threat_id = "2147931777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strictor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {55 8b ec 83 ec 0c a1 28 c0 42 00 33 c5 89 45 fc 8b 55 08 8d 45 f4 56 8b f1 89 55 f4 8d 4e 04 c6 45 f8 01 51 0f 57 c0 c7 06 24 e2 41 00 50 66 0f d6 01 e8 ba 5b 00 00 8b 4d fc 83 c4 08 8b c6 33 cd 5e e8 2e 4a 00 00 8b e5 5d c2 04 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strictor_NT_2147958657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strictor.NT!MTB"
        threat_id = "2147958657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 e8 8a 14 3a 32 55 ef 88 54 18 ff 47 3b 7d f0 75 02 33 ff 43 4e 75 cf}  //weight: 2, accuracy: High
        $x_1_2 = {7e 36 bb 01 00 00 00 8b 45 fc 8a 44 18 ff 88 45 ef f6 45 ef e0 74 15 8d 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


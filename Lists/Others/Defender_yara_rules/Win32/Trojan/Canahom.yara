rule Trojan_Win32_Canahom_A_2147597871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Canahom.gen!A"
        threat_id = "2147597871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Canahom"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b cf 42 66 ad 8b f7 33 c2 66 3d 43 3a 75 f3 ac 32 c2 aa 42 e2 f9 c3}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 3e 43 3a 74 19 50 50 e8 ?? 00 00 00 50 5a 8b fe 8d 0d ?? ?? ?? ?? 2b ce ac 32 c2 aa e2 fa 61 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {75 03 89 45 f4 83 7d f4 00 74 16 6a 00 56 e8 ?? ?? ff ff 8b 06 3d 77 61 69 74 74 05 33 c0 89 45 f4}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 62 81 3e 2d 6d 64 35 75 59 81 7e 01 6d 64 35 5b 75 50 83 eb 05 83 c6 05 8d 85 ?? ?? ff ff 50 6a 01 6a 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Canahom_C_2147609797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Canahom.gen!C"
        threat_id = "2147609797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Canahom"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fe 8b ce f7 d9 81 c1 ?? ?? ?? ?? 42 ad 8b f7 33 c2 66 3d 43 3a 75 f4 ac 32 c2 aa e2 fa c3}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 7e 01 3a 5c 74 1f e8 ?? ?? ?? ?? 8b c8 48 75 fb 83 e9 02 51 5a 8b fe 8d 0d ?? ?? ?? ?? 2b ce ac 32 c2 aa e2 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


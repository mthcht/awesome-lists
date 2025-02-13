rule Trojan_Win32_Arefty_A_2147710220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arefty.A"
        threat_id = "2147710220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arefty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 21 6a 01 53 ff 15 ?? ?? ?? ?? 85 c0 74 0d ff b5 ?? ?? ff ff ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 00 c7 45 ?? 5c 00 5f 00 c7 45 ?? 52 00 4d 00 c7 45 ?? 5f 00 00 00 85 c9 74 ?? 66 8b 01 6a 00 6a 00 6a 03 6a 00 6a 02 66 89 ?? ec 8d 45 ?? 68 00 00 00 80 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Arefty_B_2147710221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arefty.B"
        threat_id = "2147710221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arefty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca d1 f9 68 ?? ?? ?? ?? 8d 41 fb 50 8d 47 0a 50 e8 ?? ?? 00 00 83 c4 0c 8d 44 24 ?? 6a 5c}  //weight: 1, accuracy: Low
        $x_1_2 = {2b ca d1 f9 68 ?? ?? ?? ?? 8d 41 fb 50 8d 46 0a 50 e8 ?? ?? 00 00 8b 44 24 ?? 83 c4 0c 33 c9 56 66 89 48 02 8d 44 24 ?? 68 0d 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Arefty_C_2147710238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arefty.C"
        threat_id = "2147710238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arefty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 1a b8 41 00 00 00 66 89 84 24 ?? 00 00 00 b8 42 00 00 00 66 89 84 24 ?? 00 00 00 8b 35 ?? ?? ?? ?? 8d 84 24 ?? 00 00 00 50 6a 00 6a 00 6a 00 ff d6}  //weight: 2, accuracy: Low
        $x_1_2 = {81 39 2e 72 65 6c 75 08 66 81 79 04 6f 63 74 0d 42 83 c1 28 3b d7 72 e8 e9}  //weight: 1, accuracy: High
        $x_1_3 = {83 c0 0a 6a 3b 50 e8 ?? ?? 00 00 83 c4 0c 8d 84 24 ?? ?? 00 00 6a 5c 50}  //weight: 1, accuracy: Low
        $x_1_4 = "avpui.exe" ascii //weight: 1
        $x_1_5 = "wmias.exe" ascii //weight: 1
        $x_1_6 = "\\\\.\\J:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


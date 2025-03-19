rule Trojan_Win32_Mediyes_A_2147627876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mediyes.A"
        threat_id = "2147627876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 99 6a 18 83 e2 07 59 03 c2 2b cf c1 f8 03 d3 e3 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {ff 76 24 50 53 ff 15 ?? ?? ?? ?? 85 c0 75 04 32 c0 eb 19 33 c0 50 50 ff 75 ?? ff 76 28}  //weight: 1, accuracy: Low
        $x_1_3 = {68 e9 00 00 00 8b 45 0c 50 e8 ?? ?? ff ff 83 c4 08 8b 4d 08 2b 4d 0c 83 e9 05 51 8b 55 0c 83 c2 01 52 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 f4 83 3c c5 ?? ?? ?? ?? 00 74 34 8b 4d f4 83 3c cd ?? ?? ?? ?? 00 74 27 8b 55 08 52 8b 45 f4 8b 0c c5 ?? ?? ?? ?? 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Mediyes_B_2147654798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mediyes.B"
        threat_id = "2147654798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 8b 45 f0 30 08 43 3b 5e 14 72 8b fb 8b c6 e8 ?? ?? ?? ?? 89 45 f0 8d 7b ff 8b c6 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 47 04 66 8b 44 58 fe 66 31 06 8b 47 14 43 3b d8 72 83 7f 18 08 72 05 8b 77 04 eb 03 8d 77 04 8d 43 ff 3b 47 14 8d 34 5e 76 05 e8 ?? ?? ?? ?? 83 7f 18 08 72 05 8b 47 04 eb 03}  //weight: 1, accuracy: Low
        $x_1_3 = {67 02 11 17 0c 01 08 0f 0e 49 5e 18 18 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 00 00 72 00 72 00 00 00 00 00 53 00 79 00 73 00 45 00 76 00 74 00 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mediyes_C_2147656167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mediyes.C"
        threat_id = "2147656167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&sys=windows+%d.%d" wide //weight: 1
        $x_1_2 = "&sys=unknown" wide //weight: 1
        $x_1_3 = {85 c0 74 08 83 c7 01 83 ff 0a 75 e3 85 f6 74 16}  //weight: 1, accuracy: High
        $x_2_4 = {eb 02 8b c5 8a 54 38 ff 30 14 3b 83 c7 01 3b 7e 14 72 ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mediyes_D_2147656580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mediyes.D"
        threat_id = "2147656580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c5 8a 54 38 ff 30 14 3b 83 c7 01 3b 7e 14 72 ca 83 7c 24 44 10}  //weight: 1, accuracy: High
        $x_1_2 = "\\\\.\\pipe\\WinSxp" wide //weight: 1
        $x_1_3 = {64 00 57 00 57 00 1d 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 34 37 3a 3b 3f 15 0b 28 2f 05 09 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Mediyes_E_2147656981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mediyes.E"
        threat_id = "2147656981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b c5 8a 54 38 ff 30 14 3b 83 c7 01 3b 7e 14 72 ca 83 7c 24 ?? 10}  //weight: 3, accuracy: Low
        $x_1_2 = {53 00 36 00 17 00 1b 00 08 00 0d 00 22 00 3b 00 18 00 0f 00 07 00 17 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\\\.\\Global\\SysEvtC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mediyes_F_2147657569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mediyes.F"
        threat_id = "2147657569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c5 8a 54 38 ff 30 14 3b ?? 83 c7 01 3b 7e 14 72 ?? 83 7c 24 ?? 10}  //weight: 5, accuracy: Low
        $x_5_2 = "\\\\.\\pipe\\WinSxp" wide //weight: 5
        $x_1_3 = {43 2c 01 1a 11 1d 0c 24 24 06 21 3f 03 1b 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 31 05 1c 05 0a 02 15 11 2d 29 0f 0a 08 09 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mediyes_G_2147721863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mediyes.G!bit"
        threat_id = "2147721863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediyes"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 bf 03 00 00 00 83 c1 01 f7 ?? 81 f9 ?? ?? ?? ?? 75 e0 0c 00 8a 82 ?? ?? ?? ?? 30 04 ?? 8d 42 01}  //weight: 1, accuracy: Low
        $x_1_2 = {00 2f 00 63 00 20 00 22 00 73 00 63 00 20 00 64 00 65 00 6c 00 65 00 74 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "SYSTEM\\CurrentControlSet\\services\\lanmanworkstation\\Parameters" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mediyes_AZNA_2147936391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mediyes.AZNA!MTB"
        threat_id = "2147936391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 08 8b 4d 10 8a 0c 0a 03 c6 30 08 8d 42 01 29 d2 f7 75 14 46 3b 75 0c 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


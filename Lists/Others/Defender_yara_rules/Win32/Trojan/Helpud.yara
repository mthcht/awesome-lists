rule Trojan_Win32_Helpud_A_2147601462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Helpud.A"
        threat_id = "2147601462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Helpud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 53 55 55 44 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 53 58 49 48 55 44 53 00}  //weight: 1, accuracy: High
        $x_10_3 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_5_4 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Helpud_S_2147609186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Helpud.S"
        threat_id = "2147609186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Helpud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 5, accuracy: Low
        $x_1_2 = {84 c0 75 28 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 8b cb ba ?? ?? ?? ?? b8 0a 00 00 00 e8 ?? ?? ?? ?? 84 c0 74 07 8b c3 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {84 c0 75 34 8d 45 e0 e8 ?? ?? ?? ?? 8b 45 e0 50 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 8b cb ba a4 43 40 00 b8 0a 00 00 00 e8 ?? ?? ?? ?? 84 c0 74 07 8b c3 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Helpud_BA_2147614292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Helpud.BA!dll"
        threat_id = "2147614292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Helpud"
        severity = "Mid"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 6f 6f 6b 2e 64 6c 6c 00 6d 6b 73 48 6f 6f 6b 00 6d 74 7a 48 6f 6f 6b 00}  //weight: 3, accuracy: High
        $x_1_2 = "User-Agent: Intrenet Explorer" ascii //weight: 1
        $x_1_3 = "roleview.dll" ascii //weight: 1
        $x_1_4 = "soul.exe" ascii //weight: 1
        $x_1_5 = {23 33 32 37 37 30 00 00 58 50 31 00 42 75 74 74 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = "-953F-4CC8-B68F-D349FF41D677}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Helpud_BA_2147614293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Helpud.BA"
        threat_id = "2147614293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Helpud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {64 6c 6c 66 69 6c 65 00 6d 6b 73 48 6f 6f 6b 00 6d 74 7a 48 6f 6f 6b 00}  //weight: 2, accuracy: High
        $x_1_2 = {69 66 20 65 78 69 73 74 20 00 00 00 67 6f 74 6f 20}  //weight: 1, accuracy: High
        $x_1_3 = {41 56 50 2e 54 72 61 66 66 69 63 4d 6f 6e 43 6f 6e 6e 65 63 74 69 6f 6e 54 65 72 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {4b 56 58 50 5f 4d 6f 6e 69 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 79 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


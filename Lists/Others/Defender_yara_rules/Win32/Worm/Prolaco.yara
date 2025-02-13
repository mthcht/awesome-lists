rule Worm_Win32_Prolaco_A_2147616956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Prolaco.gen!A"
        threat_id = "2147616956"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Prolaco"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 8b ce 2b d6 8a 04 0a 32 44 24 0c 88 01 41 4f 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 00 00 80 50 ff 15 ?? ?? ?? ?? 8b f8 56 57 ff 15 ?? ?? ?? ?? 3d ?? ?? ?? 00 7e 12 3d ?? ?? ?? 00 7d 0b}  //weight: 1, accuracy: Low
        $x_1_3 = {3c 41 88 45 ?? 74 25 3c 42 74 21 3c 61 74 1d 3c 62 74 19 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 83 f8 02 75 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Prolaco_B_2147618738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Prolaco.gen!B"
        threat_id = "2147618738"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Prolaco"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 10 8b 45 08 31 d0 88 01 ff 45 f8 8b 45 f8 3b 45 10 72}  //weight: 2, accuracy: High
        $x_2_2 = {83 e8 32 3b 45 ?? 7d 0d 8b 45 ?? 83 c0 32 3b 45 ?? 7e 02 eb}  //weight: 2, accuracy: Low
        $x_1_3 = {ff ff 3c 61 74 ?? 8a 85 ?? ?? ff ff 3c 62 74 ?? 83 ec ?? 8d 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 02 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Prolaco_C_2147622351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Prolaco.gen!C"
        threat_id = "2147622351"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Prolaco"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 45 08 32 04 32 88 04 0a 42 39 da 75 f2}  //weight: 2, accuracy: High
        $x_2_2 = {68 00 00 00 80 53 e8 ?? ?? ?? ?? 89 c3 56 6a 00 50 e8 ?? ?? ?? ?? 89 c6 51 53 e8 ?? ?? ?? ?? 83 c4 ?? 81 fe ?? ?? ?? ?? (7e|74) ?? 81 fe ?? ?? ?? ?? 7e}  //weight: 2, accuracy: Low
        $x_1_3 = {80 fa 61 74 ?? 80 fa 62 74 ?? 83 ec ?? 56 e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 02 75}  //weight: 1, accuracy: Low
        $x_2_4 = {83 c4 0c 6a 40 68 00 30 00 00 ff 70 50 ff 70 34 ff ?? ?? ff 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6a 00 ff 70 54 57 ff 70 34 ff ?? ?? ff 95}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Prolaco_D_2147629630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Prolaco.gen!D"
        threat_id = "2147629630"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Prolaco"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "M-SEARCH * HTTP/1.1" ascii //weight: 10
        $x_10_2 = "HOST: 239.255.255.250:1900" ascii //weight: 10
        $x_10_3 = {6a 40 68 00 30 00 00 ff 70 50 ff 70 34 ff ?? ?? ff 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6a 00 ff 70 54 57 ff 70 34 ff ?? ?? ff 95}  //weight: 10, accuracy: Low
        $x_1_4 = {8a 45 08 32 04 32 88 04 0a 42 39 da 75 f2}  //weight: 1, accuracy: High
        $x_1_5 = "files/test/svchosts.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Prolaco_E_2147631316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Prolaco.gen!E"
        threat_id = "2147631316"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Prolaco"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 44 6a 00 50 e8 ?? ?? ?? ?? 83 c4 10 c7 85 ?? ?? ?? ?? 07 00 01 00 66 81 3f 4d 5a}  //weight: 2, accuracy: Low
        $x_1_2 = {31 d2 83 c4 10 8d 4b 01 eb 0e 8a 85 ?? ?? ?? ?? 32 44 32 ff 88 44 3a ff 42 39 ca 75 ed}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 0c 6a 40 68 00 30 00 00 ff 70 50 ff 70 34 ff ?? ?? ff 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6a 00 ff 70 54 57 ff 70 34 ff ?? ?? ff 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


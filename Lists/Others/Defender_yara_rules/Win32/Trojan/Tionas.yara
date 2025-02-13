rule Trojan_Win32_Tionas_A_2147690611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tionas.A!dha"
        threat_id = "2147690611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tionas"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c2 8b 4d ?? 03 4d ?? 88 41}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c2 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f9 41 7e ?? 8b 95 04 ff ff ff 0f be 84 15 10 ff ff ff 83 e8 2e 8b 8d 04 ff ff ff 88 84 0d 10 ff ff ff eb}  //weight: 1, accuracy: Low
        $x_4_4 = "dll.polymorphed.dll" ascii //weight: 4
        $x_4_5 = "78wO13YrJ0cB.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tionas_B_2147690676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tionas.B!dha"
        threat_id = "2147690676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tionas"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 08 8b 11 c7 42 14 00 00 00 00 8b 45 08 8b 08 8b 55 14 89 51 18 8b 45 08 8b 08 8b 55 0c 89 51 1c 8b 45 08 8b 08 8b 55 10 89 51 20 8b 45 08 8b 08 c7 41 24 00 00 00 00 8b 55 08 8b 02 c7 40 28 00 00 00 00 68 00 04 00 00 8b 4d 08}  //weight: 1, accuracy: High
        $x_4_2 = "78wO13YrJ0cB.dll" ascii //weight: 4
        $x_4_3 = "U25FAy93s8.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tionas_C_2147690947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tionas.C!dha"
        threat_id = "2147690947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tionas"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 0c 32 8a c2 04 ?? 8b fe 32 c8 33 c0 88 0c 32 83 c9 ff 42}  //weight: 3, accuracy: Low
        $x_1_2 = "theupdate" ascii //weight: 1
        $x_1_3 = "updater.exe" ascii //weight: 1
        $x_1_4 = "ict32.msname.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


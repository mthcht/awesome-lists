rule Trojan_Win32_ZorRoar_A_2147894758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZorRoar.A!dha"
        threat_id = "2147894758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZorRoar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {83 c4 04 89 38 6a 00 6a 00 50 68 ?? ?? ?? ?? 6a 00 6a 00 c7 40 04 [0-4] 00 00 00 ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZorRoar_B_2147894759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZorRoar.B!dha"
        threat_id = "2147894759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZorRoar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {55 8b ec 83 79 08 00 74 06 33 c0 5d c2 04 00 8b 45 08 89 41 04 c7 41 08 01 00 00 00 b8 01 00 00 00 5d c2 04 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZorRoar_C_2147894760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZorRoar.C!dha"
        threat_id = "2147894760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZorRoar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Get installed applications info failed" wide //weight: 100
        $x_100_2 = "Get info error: open registry" wide //weight: 100
        $x_100_3 = "Computer name failed" wide //weight: 100
        $x_100_4 = "User name failed" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


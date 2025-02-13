rule Trojan_Win32_Terzib_A_2147638686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Terzib.A"
        threat_id = "2147638686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Terzib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 3b c3 7e 0e 8a 88 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? eb ed}  //weight: 2, accuracy: Low
        $x_1_2 = "DEL /Q /S \"%s\\history" ascii //weight: 1
        $x_1_3 = "Cookie: /search?hl=en=q=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Terzib_A_2147638686_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Terzib.A"
        threat_id = "2147638686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Terzib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 19 8b 4d fc 8a 91 ?? ?? ?? ?? 8d 89 ?? ?? ?? ?? 30 11 ff 45 fc 39 45 fc 7c e7}  //weight: 2, accuracy: Low
        $x_1_2 = "DEL /Q /S \"%s\\history" ascii //weight: 1
        $x_1_3 = "Cookie: /search?hl=en=q=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Terzib_A_2147638686_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Terzib.A"
        threat_id = "2147638686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Terzib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DEL /Q /S \"%s\\history" ascii //weight: 1
        $x_1_2 = "Cookie: /search?hl=en=q=" ascii //weight: 1
        $x_1_3 = {c7 01 ff 55 55 ff 8b 95 24 f9 ff ff c7 42 04 00 00 00 00 8b 85 24 f9 ff ff c6 40 08 00 81 7d c0 00 60 00 00 7d 18 8b 8d 24 f9 ff ff 66 c7 41 0e ff ff c7 ?? ?? ?? ?? 00 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


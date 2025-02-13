rule Trojan_Win32_Gecedoc_A_2147609612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gecedoc.A"
        threat_id = "2147609612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gecedoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "MP3: %s: already injected" wide //weight: 2
        $x_2_2 = "WMA: %s: already injected" wide //weight: 2
        $x_1_3 = "URLAndExitCommandsEnabled" wide //weight: 1
        $x_1_4 = "URLANDEXIT" wide //weight: 1
        $x_2_5 = {64 5f f0 0b 4d f8 b4 11 89 96 40 00 00 07 f9 3f a6 35 2a}  //weight: 2, accuracy: High
        $x_2_6 = {8d 44 00 02 50 8b 4d 10 51 6a 01 6a 00 8b 55 0c 52 8b 45 f8 50 ff 15 [0-2] 40 00 85 c0 75 09 c7 45 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Hitbrovi_B_2147696661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hitbrovi.B!dha"
        threat_id = "2147696661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitbrovi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0" wide //weight: 1
        $x_1_2 = "/default.asp" wide //weight: 1
        $x_1_3 = "fba00000002407" ascii //weight: 1
        $x_1_4 = "c8ca0000002336" ascii //weight: 1
        $x_1_5 = "192.168.100." ascii //weight: 1
        $x_2_6 = "WindowsUpdateReaver" wide //weight: 2
        $x_2_7 = "WindowsUpdateTimer" wide //weight: 2
        $x_3_8 = "LOuWApl" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hitbrovi_E_2147697467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hitbrovi.E"
        threat_id = "2147697467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitbrovi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Owning PCI bus" wide //weight: 1
        $x_1_2 = "Look ma, no thread id! \\o/" wide //weight: 1
        $x_1_3 = "Updating CPU microcode" wide //weight: 1
        $x_1_4 = "%s\\%d02322.bat" wide //weight: 1
        $x_1_5 = "WindowsUpdateReaver" wide //weight: 1
        $x_1_6 = {c7 44 24 0c 25 00 73 00 c7 44 24 10 5c 00 25 00 c7 44 24 14 53 00 2e 00 c7 44 24 18 65 00 78 00 c7 44 24 1c 65 00 00 00 e8 ?? ?? ?? ?? 68 fe ff 00 00 8b f0 e8 ?? ?? ?? ?? 83 c4 08 6a 00 6a 07 56 6a 00 8b f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


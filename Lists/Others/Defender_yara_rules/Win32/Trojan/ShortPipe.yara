rule Trojan_Win32_ShortPipe_A_2147897225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShortPipe.A!dha"
        threat_id = "2147897225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShortPipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript.exe" wide //weight: 1
        $x_1_2 = "trash.dat" wide //weight: 1
        $x_1_3 = "trash.dll" wide //weight: 1
        $x_1_4 = "//e:vbScript" wide //weight: 1
        $x_1_5 = "//b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_ShortPipe_A_2147897225_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShortPipe.A!dha"
        threat_id = "2147897225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShortPipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "wscript.exe" wide //weight: 100
        $x_1_2 = "~e.vol" wide //weight: 1
        $x_1_3 = "~.ini" wide //weight: 1
        $x_1_4 = "~.tmp" wide //weight: 1
        $x_1_5 = "trash.dll" wide //weight: 1
        $x_1_6 = "trash.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ShortPipe_B_2147897226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShortPipe.B!dha"
        threat_id = "2147897226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShortPipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 74 00 79 00 6c 00 65 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 24 00 28 00 67 00 63 00 [0-16] 7c 00 6f 00 75 00 74 00 2d 00 73 00 74 00 72 00 69 00 6e 00 67 00 29 00 7c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 6e 00 6f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Worm_Win32_Verst_B_2147632872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Verst.B"
        threat_id = "2147632872"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Verst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\MSrtn\\value1" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_3 = "KAENA_HOOK" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "ZwOpenProcess" ascii //weight: 1
        $x_1_6 = "aUtoRuN.iNF" wide //weight: 1
        $x_1_7 = "srtserv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Verst_A_2147632981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Verst.A"
        threat_id = "2147632981"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Verst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot" ascii //weight: 2
        $x_2_2 = "Icon=%system%\\shell32.dll,4" ascii //weight: 2
        $x_2_3 = "shell\\open\\Command=" ascii //weight: 2
        $x_2_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common AppData" ascii //weight: 2
        $x_2_5 = "!ADH:RC4+RSA" ascii //weight: 2
        $x_2_6 = "ShellHWDetection" ascii //weight: 2
        $x_2_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\MSrtn\\value" ascii //weight: 2
        $x_2_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\srtserv" ascii //weight: 2
        $x_1_9 = "http://psynergi.dk/data" ascii //weight: 1
        $x_1_10 = "http://kubusse.ru/data" ascii //weight: 1
        $x_1_11 = "http://s-elisa.ru/data" ascii //weight: 1
        $x_1_12 = "http://eda.ru/data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Verst_A_2147633930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Verst.A"
        threat_id = "2147633930"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Verst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 ee f1 f1 f2 e0 ed ee e2 eb e5 ed e8 e5 20 e4 ee f1 f2 f3 ef e0 20 ea 20 57 4d 49 44 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 80 7d 08 01 75 1c 6a 00 a1 ?? ?? ?? ?? 50 b8 ?? ?? ?? ?? 50 6a 03 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb 12 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\MSrtn\\p" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


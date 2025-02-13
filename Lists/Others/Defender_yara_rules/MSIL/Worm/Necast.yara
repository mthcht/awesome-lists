rule Worm_MSIL_Necast_A_2147638824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Necast.A"
        threat_id = "2147638824"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Necast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 65 74 49 6e 73 74 61 6e 63 65 00 4d 61 69 6e 00 45 00 5a 49 50 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 01 00 00 70 28 20 00 00 0a 73 21 00 00 0a 0a 06 72 05 00 00 70 6f 22 00 00 0a 74 09 00 00 1b 28 14 00 00 06 28 23 00 00 0a 6f 24 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Necast_B_2147643774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Necast.B"
        threat_id = "2147643774"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Necast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 00 65 00 72 00 73 00 69 00 73 00 74 00 61 00 6e 00 74 00 58 00 2a 00 58 00 ?? ?? 53 00 70 00 72 00 65 00 61 00 64 00 58 00 2a 00 58 00}  //weight: 2, accuracy: Low
        $x_2_2 = {4b 00 69 00 6c 00 6c 00 40 00 [0-16] 55 00 53 00 42 00 2c 00 [0-4] 52 00 61 00 72 00 2c 00 5a 00 69 00 70 00}  //weight: 2, accuracy: Low
        $x_1_3 = "PC InfoX*X==" wide //weight: 1
        $x_1_4 = "Server InfoX*X==" wide //weight: 1
        $x_1_5 = "Firewall BypassX*X" wide //weight: 1
        $x_1_6 = "firewall set opmode disable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Necast_D_2147647874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Necast.D"
        threat_id = "2147647874"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Necast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 88 13 00 00 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 04 16 0d 38 a3 00 00 00 11 04 09 9a 0a 06 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {4b 00 69 00 6c 00 6c 00 40 00 [0-16] 55 00 53 00 42 00 2c 00 [0-4] 52 00 61 00 72 00 2c 00 5a 00 69 00 70 00}  //weight: 2, accuracy: Low
        $x_1_3 = "PC InfoX*X==" wide //weight: 1
        $x_1_4 = "Server InfoX*X==" wide //weight: 1
        $x_1_5 = "Firewall BypassX*X" wide //weight: 1
        $x_1_6 = "firewall set opmode disable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Necast_F_2147648138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Necast.F"
        threat_id = "2147648138"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Necast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "win7mailer411@gmail.com" wide //weight: 1
        $x_1_2 = "\\svchost..exe" wide //weight: 1
        $x_1_3 = "\\Documents\\suchost..exe" wide //weight: 1
        $x_1_4 = "benhurdavies20" wide //weight: 1
        $x_1_5 = "\\Windows\\system\\wsystem.vx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_MSIL_Necast_H_2147654284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Necast.H"
        threat_id = "2147654284"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Necast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "firewall add allowedprogram X Y ENABLE" wide //weight: 5
        $x_5_2 = "delete allowedprogram X" wide //weight: 5
        $x_5_3 = "cmd.exe /k ping 0 & del \"" wide //weight: 5
        $x_5_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 5
        $x_5_5 = "PROCESSOR_ARCHITECTURE" wide //weight: 5
        $x_5_6 = {03 ae 00 01 03 22 21 01}  //weight: 5, accuracy: High
        $x_5_7 = {07 57 00 69 00 6e 00 00 03 ae 00 ?? 03 22 21}  //weight: 5, accuracy: Low
        $x_1_8 = "U0VFX01BU0tfTk9aT05FQ0hFQ0tT" wide //weight: 1
        $x_1_9 = "SEE_MASK_NOZONECHECKS" wide //weight: 1
        $x_1_10 = "XE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFBvbGljaWVzXFN5c3RlbQ==" wide //weight: 1
        $x_1_11 = "jn.redirectme.net:305" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*) and 2 of ($x_1_*))) or
            ((7 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Necast_J_2147666565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Necast.J"
        threat_id = "2147666565"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Necast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 57 00 69 00 6e 00 00 03 ae 00 ?? 03 22 21}  //weight: 1, accuracy: Low
        $x_1_2 = "U0VFX01BU0tfTk9aT05FQ0hFQ0tT" wide //weight: 1
        $x_1_3 = "cmd.exe /k ping 0 & del" wide //weight: 1
        $x_1_4 = "netsh firewall add allowedprogram" wide //weight: 1
        $x_1_5 = "[ENTER]" wide //weight: 1
        $x_1_6 = "[endof]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


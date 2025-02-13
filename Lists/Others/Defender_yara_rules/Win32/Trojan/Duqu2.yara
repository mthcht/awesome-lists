rule Trojan_Win32_Duqu2_E_2147696040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duqu2.E!dha"
        threat_id = "2147696040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duqu2"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8d 04 10 49 83 c0 01 41 8a 0c 01 32 08 49 83 ea 01 42 88 ?? ?? ?? ?? 00 00 75 e4 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Duqu2_B_2147696041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duqu2.B!dha"
        threat_id = "2147696041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duqu2"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {8d 16 8b 1a f7 db 0f cb c1 c3 03 0f cb 81 f3}  //weight: 100, accuracy: High
        $x_1_2 = "&a=mouse" wide //weight: 1
        $x_1_3 = "delayed-auto" wide //weight: 1
        $x_1_4 = "SP%d%c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Duqu2_D_2147696042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duqu2.D!dha"
        threat_id = "2147696042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duqu2"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\{3787DEAF-2EFA-BDCA-EFAD-172ED35ABCD4}" wide //weight: 1
        $x_1_2 = {8d 3a 8b 07 35 ?? ?? ?? ?? 0f c8 c1 c8 06 0f c8 89 03 83 c2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Duqu2_A_2147696043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duqu2.A!dha"
        threat_id = "2147696043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duqu2"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 00 00 00 00 4c 8b d1 0f 05 c3 ?? b8 00 00 00 00 8d 54 24 04 cd 2e c2 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = "SetClassLongA" ascii //weight: 10
        $x_10_3 = "DestroyWindow" ascii //weight: 10
        $x_10_4 = "RegisterClassA" ascii //weight: 10
        $x_1_5 = {b9 82 00 00 c0 0f 32}  //weight: 1, accuracy: High
        $x_1_6 = {b9 76 01 00 00 0f 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


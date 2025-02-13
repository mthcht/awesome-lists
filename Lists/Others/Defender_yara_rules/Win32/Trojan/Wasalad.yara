rule Trojan_Win32_Wasalad_A_2147723142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wasalad.A"
        threat_id = "2147723142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wasalad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 3a 5c 62 61 63 6b 77 61 72 64 5c 69 6e 63 68 5c 65 6e 75 6d 65 72 61 74 69 6f 6e 5c 41 74 6d 65 6c 5c 6e 65 63 65 73 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wasalad_A_2147723157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wasalad.A!!Wasalad.gen!A"
        threat_id = "2147723157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wasalad"
        severity = "Critical"
        info = "Wasalad: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ba 00 00 00 00 b9 00 00 00 00 b8 00 00 00 00 52 6a 01 51 ff d0 c3}  //weight: 10, accuracy: High
        $x_10_2 = {68 58 02 00 00 ff 15 ?? ?? ?? ?? eb f3}  //weight: 10, accuracy: Low
        $x_10_3 = {0f 31 8d 0d d0 60 10 01 0b 01 c1 d0 02 05 ef be ad de 1b c2 89 01 13 01 03 01 d1 d0 89 01 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wasalad_B_2147723159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wasalad.B"
        threat_id = "2147723159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wasalad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 3a 5c 70 6f 73 74 6d 61 73 74 65 72 5c 6d 65 72 67 65 5c 50 65 61 73 61 6e 74 73 5c 42 69 6c 6c 79 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


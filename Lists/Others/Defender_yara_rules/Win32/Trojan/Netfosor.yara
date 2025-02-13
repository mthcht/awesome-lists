rule Trojan_Win32_Netfosor_A_2147685123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netfosor.A!dha"
        threat_id = "2147685123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netfosor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 0a 00 00 00 51 b9 32 00 00 00 83 f0 3e 40 e2 fa 59 9d 58 68 0c 63 40 00 50 9c b8 0a 00 00 00 51 b9 32 00 00 00 83 f0 3e 40 e2 fa}  //weight: 1, accuracy: High
        $x_1_2 = "/upload?%d" wide //weight: 1
        $x_1_3 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%d|%d" wide //weight: 1
        $x_1_4 = "computer=%s&lanip=%s&uid=%s&os=%s&relay=%d&data=%s" wide //weight: 1
        $x_1_5 = {2f 00 72 00 65 00 73 00 75 00 6c 00 74 00 3f 00 25 00 (64 00|6c 00)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Netfosor_B_2147707231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netfosor.B!dha"
        threat_id = "2147707231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netfosor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 69 74 64 65 66 65 6e 64 65 72 20 32 30 31 33 00 00 00 5c 4b 61 73 70 65 72 73 6b 79 20 4c 61 62 5c 4b 61 73 70 65 72 73 6b 79 20 49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 32 30 31 33}  //weight: 1, accuracy: High
        $x_1_2 = "seccenter.xxx" ascii //weight: 1
        $x_1_3 = {48 89 47 ff 8b 05 ?? ?? ?? ?? 48 8d 8c 24 90 01 00 00 89 47 07 0f b7 05 ?? ?? ?? ?? ba 00 00 00 40 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 66 89 47 0b ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Netfosor_D_2147707232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netfosor.D!dha"
        threat_id = "2147707232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netfosor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 64 ff 15 ?? ?? ?? ?? e9 ef 00 00 00 39 9d ?? ?? ?? ?? 76 eb be 01 08 00 00 56 33 c0 8d bd ?? ?? ?? ?? 6a 40 ab ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "loop?c=%s&l=%s&o=%s&u=%s&r=%d&t=%d" wide //weight: 1
        $x_1_3 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" wide //weight: 1
        $x_1_4 = "/down?p=%ld&l=%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


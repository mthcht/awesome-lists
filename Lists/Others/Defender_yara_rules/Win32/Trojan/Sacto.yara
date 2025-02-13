rule Trojan_Win32_Sacto_A_2147696333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sacto.A!dha"
        threat_id = "2147696333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 48 66 81 38 4d 5a 75 41 8b 48 3c 03 c8 81 39 50 45 00 00 75 34}  //weight: 1, accuracy: High
        $x_1_2 = {8b 78 0c 42 89 78 14 8b 78 08 89 78 10 33 ff 66 8b 79 06 8b c6 83 c6 28 3b d7 7c e4 5f}  //weight: 1, accuracy: High
        $x_1_3 = {8b f0 83 c4 18 85 f6 74 27 57 8d 7c 24 08 83 c9 ff 33 c0 f2 ae f7 d1}  //weight: 1, accuracy: High
        $x_1_4 = {76 17 8a 54 24 10 8b 4c 24 08 53 8a 1c 08 02 da 88 1c 08 40 3b c6 72 f3 5b}  //weight: 1, accuracy: High
        $x_1_5 = "\\SslMM" ascii //weight: 1
        $x_1_6 = {25 77 73 3a 25 64 2f 25 64 25 73 25 64 48 54 54 50 2f 31 2e 31 00}  //weight: 1, accuracy: High
        $x_1_7 = {6f 63 74 61 73 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_8 = ".51vip.biz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Sacto_B_2147712013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sacto.B!bit"
        threat_id = "2147712013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacto"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "    .exe" wide //weight: 1
        $x_1_2 = "U-SerialNumber: %X-%X" wide //weight: 1
        $x_1_3 = "onfig.tmp" wide //weight: 1
        $x_1_4 = "\\MSN.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


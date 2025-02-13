rule Trojan_Win32_SamScissors_CO_2147843891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SamScissors.CO"
        threat_id = "2147843891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SamScissors"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d0 ba 82 84 1e 00 b9 40 00 00 00 ff 15 ?? ?? ?? ?? 49 89 06 48 85 c0 0f 84 59 02 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "places.sqlite" wide //weight: 1
        $x_1_3 = "SELECT url, title FR" wide //weight: 1
        $x_1_4 = {25 00 73 00 20 00 20 00 20 00 3a 00 20 00 20 00 20 00 25 00 73 00 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SamScissors_A_2147844301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SamScissors.A"
        threat_id = "2147844301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SamScissors"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ce fe ed fa ce 7d 61 d5 99 70 a9 00 4e 8c 29 43 c5 f6 cb 41 6d b2 ee 5e 54 37 71 21 26 50 a1 f1 1f c8 2c 60 b0 ef 05 d4 32 41 5d 95 59 07 9c e7 9b 29 7e 8f 9f 54 57 91 45 33 d4 3d 7d 07 77 01 47 d1 07 49 22 cd fc a2 18 6f 84 0a db f2 e0 25}  //weight: 2, accuracy: High
        $x_2_2 = "D3DCOMPILER_47.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SamScissors_SA_2147844611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SamScissors.SA"
        threat_id = "2147844611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SamScissors"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d8 e8 ?? ?? ?? ?? 44 8b c0 b8 ?? ?? ?? ?? 41 f7 e8 8d 83 ?? ?? ?? ?? c1 fa ?? 8b ca c1 e9 ?? 03 d1 69 ca ?? ?? ?? ?? 48 8d 55 ?? 44 2b c1 48 8d 4c 24 ?? 41 03 c0 3b 00 33 c9 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 11 84 24 ?? ?? ?? ?? 44 8b 06 8b dd bf 15 00 b8 ?? ?? ?? ?? 41 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SamScissors_SB_2147844612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SamScissors.SB"
        threat_id = "2147844612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SamScissors"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "https://raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" ascii //weight: 5
        $x_1_2 = "__tutma" ascii //weight: 1
        $x_1_3 = "__tutmc" ascii //weight: 1
        $x_1_4 = {33 c1 45 8b ca 8b c8 c1 e9 ?? 33 c1 81 c2 ?? ?? ?? ?? 8b c8 c1 e1 ?? 33 c1 41 8b c8 1e 00 c1 e1}  //weight: 1, accuracy: Low
        $x_1_5 = {ff d5 48 85 c0 74 ?? 81 7b ?? ca 7d 0f 00 75 ?? 48 8d 54 24 ?? 48 8d 4c 24 ?? ff d0 8b f8 44 8b 44 24 ?? 4c 8d 4c 24 ?? ba 00 10 00 00 48 8b cd ff 15 3b 00 ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SamScissors_SC_2147844613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SamScissors.SC"
        threat_id = "2147844613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SamScissors"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\%s\\%s\\%s" ascii //weight: 1
        $x_1_2 = "%s.old" ascii //weight: 1
        $x_1_3 = "******************************** %s ******************************" ascii //weight: 1
        $x_1_4 = "HostName: %s\\r\\nDomainName: %s\\r\\nOsVersion: %d.%d.%d\\r\\n\\r\\n" ascii //weight: 1
        $x_1_5 = "%s\\r\\nDomainName: %s\\r\\nOsVersion: %d.%d.%d\\r\\n\\r\\n" ascii //weight: 1
        $x_1_6 = "AppData\\Local\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_7 = "SELECT url, title FROM urls ORDER BY id DESC LIMIT" ascii //weight: 1
        $x_2_8 = "\\3CXDesktopApp\\config.json" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


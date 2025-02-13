rule Trojan_Win32_Chadivendo_STA_2147779209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chadivendo.STA"
        threat_id = "2147779209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chadivendo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 04 00 00 6a 00 6a 00 6a 06 [0-10] ff 15 ?? ?? ?? ?? 85 c0 [0-6] c7 00 ?? ?? ?? ?? c7 40 04 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 49 1f 20 03 c7 40 04 99 df c1 18 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {80 4f 00 00 00 5f ff ff ff ff 47 6c 6f 62 61 6c 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chadivendo_STB_2147779210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chadivendo.STB"
        threat_id = "2147779210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chadivendo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 3a 8a c1 c0 e1 02 c0 f8 06 0a c1 88 04 3a 42 3b d6 7c eb}  //weight: 1, accuracy: High
        $x_1_2 = {8b c3 99 f7 fe 8a 04 3a 30 [0-5] 43 81 fb ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 f0 c7 45 f0 ?? ?? ?? ?? 50 8b 45 fc c7 45 f4 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {80 4f 00 00 00 5f ff ff ff ff 47 6c 6f 62 61 6c 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chadivendo_STC_2147779211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chadivendo.STC"
        threat_id = "2147779211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chadivendo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 [0-16] ff 15 ?? e0 00 10 ff 15 ?? e0 00 10 68 ?? ?? ?? 10 ff 15 ?? e0 00 10}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 [0-16] 44 65 62 75 67 42 72 65 61 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 54 65 6d 70 5c 65 64 67 ?? ?? ?? ?? 2e 74 6d 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chadivendo_STD_2147779219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chadivendo.STD"
        threat_id = "2147779219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chadivendo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 72 76 69 63 65 44 6c 6c [0-10] 00 65 64 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 77 6c 69 62 2e 64 6c 6c [0-80] 73 63 20 73 74 61 72 74 20 22 25 73 22}  //weight: 1, accuracy: Low
        $x_1_3 = "f2032.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chadivendo_STE_2147779250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chadivendo.STE"
        threat_id = "2147779250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chadivendo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? 01 10 ?? ?? ?? ?? ff 15 ?? e0 00 10 [0-6] 68 ?? ?? 01 10 ff 15 ?? e0 00 10}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 01 01 01 01 83 f9 20 0f 86 df 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 72 76 69 63 65 52 65 73 70 6f 6e 63 65 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


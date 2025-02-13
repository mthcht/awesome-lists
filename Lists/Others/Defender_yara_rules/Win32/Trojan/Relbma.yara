rule Trojan_Win32_Relbma_A_2147605680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relbma.A"
        threat_id = "2147605680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relbma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 0c 80 b0 ?? ?? 40 00 ?? 40 3b c6 72 f4 46 56 57 6a 03}  //weight: 1, accuracy: Low
        $x_1_2 = {40 00 6a 66 e8 ?? ?? ff ff 68 ?? ?? 40 00 6a 6a e8 ?? ?? ff ff 68 ?? ?? 40 00 6a 69 e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {76 09 80 34 38 ?? 40 3b c6 72 f7 8a 45 0f 53 6a 00 8d}  //weight: 1, accuracy: Low
        $x_1_4 = "protect.advancedcleaner.com" ascii //weight: 1
        $x_1_5 = "Microsoft Security Guard\" binterval" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Relbma_A_2147605681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relbma.A!dll"
        threat_id = "2147605681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relbma"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {2b d6 80 b4 05 f0 fd ff ff ?? 80 b4 05 f1 fd ff ff ?? 80 b4 05 f2 fd ff ff ?? 83 c0 03 8d 34 02 8d b4 35 f1 fd ff ff 3b f1 72 d7 3b c1 73 08 80 b4 05 f0 fd ff ff ?? 8d 50 01}  //weight: 9, accuracy: Low
        $x_2_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 52 75 6e 4d 61 69 6e 00}  //weight: 2, accuracy: High
        $x_2_3 = {6d 62 75 72 6c 00 00 00 62 75 72 6c 00 00 00 00 6d 62 74 65 78 74 00 00 62 74 65 78 74 00}  //weight: 2, accuracy: High
        $x_1_4 = "yandex" ascii //weight: 1
        $x_1_5 = "clickreferer" ascii //weight: 1
        $x_1_6 = "feed" ascii //weight: 1
        $x_1_7 = {00 5f 57 53 43 4c 41 53 5f 00}  //weight: 1, accuracy: High
        $x_1_8 = "popurl" ascii //weight: 1
        $x_2_9 = {63 6c 61 73 73 3d 79 73 63 68 74 74 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_9_*))) or
            (all of ($x*))
        )
}


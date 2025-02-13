rule Trojan_Win32_FoggyWeb_A_2147794646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FoggyWeb.A!dha"
        threat_id = "2147794646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FoggyWeb"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 f9 40 72 75 66 0f 6f 15 ?? ?? ?? ?? 48 8b d1 48 83 e2 c0 66 0f 1f 44 00 00 f3 0f 6f 44 04 ?? 66 0f 6f ca 66 0f ef c8 f3 0f 7f 4c 04 ?? f3 0f 6f 44 05 ?? 66 0f 6f ca 66 0f ef c8}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f 6f ca 66 0f ef c8 f3 0f 7f 4c 05 ?? f3 0f 6f 44 05 ?? 66 0f 6f ca 66 0f ef c8 f3 0f 7f 4c 05 ?? 48 83 c0 40 48 3b c2 72 ?? 48 3b c1 73 ?? 66 90 80 74 04 70 ?? 48 ff c0 48 3b c1}  //weight: 1, accuracy: Low
        $x_1_3 = {44 89 03 4d 8d 5b f0 41 8b c9 41 8b d2 41 8b c5 44 8b d1 44 8b ?? 41 c1 c2 05 41 8b 43 0c 45 8b e8 41 33 c0 41 c1 c9 09 44 2b c8 44 8b c2}  //weight: 1, accuracy: Low
        $x_1_4 = {45 33 4b 10 44 89 4b 04 41 8b 43 14 41 33 c1 41 c1 c0 03 44 2b d0 45 33 53 10 44 89 53 08 41 8b ?? 41 33 43 18 44 2b c0 45 33 43 10 49 83 ef 01 44 89 43 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_FoggyWeb_A_2147794646_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FoggyWeb.A!dha"
        threat_id = "2147794646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FoggyWeb"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 01 ff 50 18 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 4c 24 ?? 4c 8d 44 24 ?? 48 8d 54 24 ?? 48 8b 01 ff 50 70 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 ?? 48 8d 54 24 ?? 48 8b 01 ff 50 70 85 c0 0f 85 ?? ?? ?? ?? 48 8b 4c 24 ?? 4c 8d 44 24 ?? 48 8b 54 24 ?? 48 8b 01 ff 50 78}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 01 ff 50 10 48 8b 4c 24 ?? 48 8b 01 ff 50 10 48 8b 4c 24 ?? 4c 8d 44 24 ?? 48 8b 54 24 ?? 48 8b 01 ff 50 78 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 01 ff 90 80 00 00 00 48 8b 4c 24 ?? 48 8b 01 ff 50 10 48 8b 4c 24 ?? 48 8b 01 ff 50 10 48 8b 4c 24 ?? 48 8b 01 ff 50 10}  //weight: 1, accuracy: Low
        $x_2_5 = {48 8b 4c 24 ?? 48 8b 01 4c 8d 44 24 ?? 48 8b 17 ff 90 48 01 00 00 85 c0 75 ?? 48 8b 4c 24 ?? 48 8b 01 ff 50 10 b3 01 eb ?? 32 db 41 8b c6 f0 0f c1 46 10 83 f8 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


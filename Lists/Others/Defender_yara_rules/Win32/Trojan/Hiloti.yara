rule Trojan_Win32_Hiloti_A_133275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hiloti.gen!A"
        threat_id = "133275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiloti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c9 3b de 76 08 30 0c 01 41 3b cb 72 f8 50 ff 15}  //weight: 3, accuracy: High
        $x_2_2 = {75 36 66 83 3d ?? ?? ?? ?? 61 75 2c 66 83 3d ?? ?? ?? ?? 67 75 22 66 83 3d ?? ?? ?? ?? 69 75 18 66 83 3d ?? ?? ?? ?? 63}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 46 0c 8b 4e 10 03 c1 89 46 0c eb cd 56 8b f1 8d 46 04}  //weight: 1, accuracy: High
        $x_1_4 = {6a 24 eb 02 6a 1c ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = "&clver=" wide //weight: 1
        $x_1_6 = "%s%x.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hiloti_B_139879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hiloti.gen!B"
        threat_id = "139879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiloti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 40 10 3d 00 00 03 00 0f 8f ?? 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 42 18 2d 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = {c9 83 04 24 ?? c2 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hiloti_A_144490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hiloti.A"
        threat_id = "144490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiloti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zfsearch.com" wide //weight: 1
        $x_1_2 = "http://%s/js3.php?kws=%%s&q=%%s&%%s" wide //weight: 1
        $x_1_3 = "Referer:" wide //weight: 1
        $x_1_4 = "redirect" wide //weight: 1
        $x_1_5 = "searchterm=" wide //weight: 1
        $x_1_6 = "keyword=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hiloti_C_147136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hiloti.gen!C"
        threat_id = "147136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiloti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "____TESTRES____ ______________" wide //weight: 1
        $x_1_2 = "t0002.err.size%08x.err%08x" wide //weight: 1
        $x_1_3 = "rundll32.exe \"%s\",iep" wide //weight: 1
        $x_1_4 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322)" wide //weight: 1
        $x_1_5 = "tick=%010d&pid=%04x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hiloti_D_147238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hiloti.gen!D"
        threat_id = "147238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiloti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c2 88 04 ?? 42 3b}  //weight: 2, accuracy: Low
        $x_2_2 = {30 04 38 40 3b (45 fc|c6) 72}  //weight: 2, accuracy: Low
        $x_2_3 = {83 fe 64 73 18 66 83 78 08 01 75 0b 8b 48 18 89 8c b5 ?? ?? ff ff 46 8b 00 3b c3 75 e3}  //weight: 2, accuracy: Low
        $x_2_4 = {6a 2f 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 74 04 66 83 20 00 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 83 f8 04 7e 24}  //weight: 2, accuracy: Low
        $x_2_5 = {66 81 3a 4d 5a 75 23 8b 4a 3c 03 ca 81 39 50 45 00 00 75 16 0f b7 49 16 f6 c1 02 74 0d 66 81 e1 00 20 66 81 f9 00 20}  //weight: 2, accuracy: High
        $x_2_6 = {66 81 3e 4d 5a 75 20 8b 46 3c 03 c6 81 38 50 45 00 00 75 13 0f b7 40 16 84 c2 74 0b 66 25 00 20 66 3d 00 20 0f 95 c1 f6 d9 1b c9 83 e1 04}  //weight: 2, accuracy: High
        $x_2_7 = {33 c0 0f a2 89 5d ?? 89 55 ?? 89 4d ?? b8 01 00 00 00 0f a2 33 45 ?? 33 55 ?? 03 55 ?? 8b 4d ?? 03 11 33 c2 89 45 ?? 61}  //weight: 2, accuracy: Low
        $x_2_8 = {81 38 8b ff 55 8b 75 0a 80 78 04 ec 0f 84 51 01 00 00}  //weight: 2, accuracy: High
        $x_1_9 = {6c 00 64 00 ?? ?? 5f 00 65 00 3d 00 25 00 31 00 64 00 26 00 63 00 6c 00 6e 00 74 00 5f 00 65 00 3d 00 25 00 31 00 64 00}  //weight: 1, accuracy: Low
        $x_1_10 = "?kws=%%s&q=%%s&%%s" wide //weight: 1
        $x_1_11 = "&tick=%010d" wide //weight: 1
        $x_1_12 = "&flags=%08x&srch=%08x&clck=%08x&newtabwin=%s" wide //weight: 1
        $x_1_13 = "&delay=%08d" wide //weight: 1
        $x_1_14 = {6f 00 73 00 76 00 65 00 72 00 3d 00 25 00 64 00 ?? ?? 25 00 64 00}  //weight: 1, accuracy: Low
        $x_1_15 = "tck=%010d" wide //weight: 1
        $x_1_16 = "ver=%d_%d" wide //weight: 1
        $x_1_17 = {2f 00 67 00 65 00 74 00 32 00 2e 00 70 00 68 00 70 00 00 00 00 00 77 00 69 00 6e 00 73 00 74 00 61 00 30 00 5c 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00}  //weight: 1, accuracy: High
        $x_2_18 = {50 66 c7 45 f0 61 00 66 c7 45 f2 65 00 66 c7 45 f4 69 00 66 c7 45 f6 6f 00 66 c7 45 f8 75 00 ff d6}  //weight: 2, accuracy: High
        $x_2_19 = {33 f6 66 c7 45 e8 73 00 66 c7 45 ea 61 00 66 c7 45 ec 76 00 66 c7 45 ee 65 00 66 c7 45 f0 6f 00 66 c7 45 f2 6c 00 66 c7 45 f4 64 00 66 89 75 f6}  //weight: 2, accuracy: High
        $x_1_20 = {30 04 38 40 3b c1 76 f8}  //weight: 1, accuracy: High
        $x_2_21 = {80 f1 10 c0 f9 04 80 e1 0f 80 f9 09 0f be c9 7e 05 83 c1 37 eb 03 83 c1 30}  //weight: 2, accuracy: High
        $x_1_22 = {0f b6 cd 03 c1 99 59 f7 f9 [0-18] 8b da 83 c3 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hiloti_E_153143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hiloti.gen!E"
        threat_id = "153143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiloti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "rundll32.exe \"%s\",iep" wide //weight: 2
        $x_1_2 = {66 00 66 00 70 00 70 00 63 00 3a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 00 30 00 31 00 30 00 64 00 2e 00 25 00 30 00 38 00 78 00 2e 00 25 00 30 00 32 00 64 00 2e 00 25 00 73 00 2e 00 25 00 73 00 2e 00 25 00 73 00 2e 00 25 00 73 00 2e 00 25 00 73 00 2e 00 25 00 73 00 2e 00 5f 00 74 00 5f 00 69 00 2e 00 25 00 30 00 34 00 78 00 2e 00 25 00 73 00 2e 00 25 00 64 00 2e 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 00 61 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {26 00 75 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {26 00 61 00 64 00 6d 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {26 00 5f 00 74 00 63 00 6b 00 3d 00 25 00 30 00 31 00 30 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {26 00 70 00 72 00 6f 00 63 00 3d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


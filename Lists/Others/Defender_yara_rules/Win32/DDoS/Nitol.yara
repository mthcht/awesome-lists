rule DDoS_Win32_Nitol_A_2147644209_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.A"
        threat_id = "2147644209"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ") Gecko/20080808 Firefox/%d.0" ascii //weight: 1
        $x_1_2 = ".htmGET ^&&%$%$^%$#^&**(" ascii //weight: 1
        $x_1_3 = {00 4e 61 74 69 6f 6e 61 6c}  //weight: 1, accuracy: High
        $x_1_4 = {ff d5 68 00 e9 a4 35 66 89}  //weight: 1, accuracy: High
        $x_1_5 = {6e 65 78 25 64 00 00 00 6e 65 74 73 76 63 73 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DDoS_Win32_Nitol_B_2147649615_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.B"
        threat_id = "2147649615"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET ^&&%$%$^%$#^&**" ascii //weight: 1
        $x_1_2 = "Gecko/20080808 Firefox/%d.0" ascii //weight: 1
        $x_1_3 = "; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" ascii //weight: 1
        $x_1_4 = {53 54 4f 52 4d 44 44 4f 53 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 5c 2e 5c 50 61 73 73 74 68 72 75 00}  //weight: 1, accuracy: High
        $x_1_7 = "Referer: http://%s:80/http://%s" ascii //weight: 1
        $x_1_8 = {23 30 25 73 21 00}  //weight: 1, accuracy: High
        $x_1_9 = {83 c4 04 83 c0 61 50 6a 1a e8}  //weight: 1, accuracy: High
        $x_1_10 = {00 55 44 50 57 5a 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 54 43 50 51 4c 00}  //weight: 1, accuracy: High
        $x_1_12 = {83 c0 03 33 d2 0f af c6 f7 74 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule DDoS_Win32_Nitol_C_2147660363_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.C"
        threat_id = "2147660363"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_2 = "GET ^&&%$%$^%$#^&**" ascii //weight: 1
        $x_1_3 = "Gecko/20080808 Firefox/%d.0" ascii //weight: 1
        $x_1_4 = "Referer: http://%s:80/http://%s" ascii //weight: 1
        $x_1_5 = "192.168.1.244" ascii //weight: 1
        $x_1_6 = {25 75 20 4d 42 [0-4] 25 75 20 4d 48 7a [0-4] 7e 4d 48 7a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule DDoS_Win32_Nitol_D_2147664034_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.D"
        threat_id = "2147664034"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".htmGET ^&&%$%$^%$#^&**(*((&*^%$##$%^&*(*&^%$%^&*.htmGET ^" ascii //weight: 1
        $x_1_2 = {ff d5 68 00 e9 a4 35 66 89}  //weight: 1, accuracy: High
        $x_1_3 = {33 d2 8a 11 03 c2 8b c8 25 ff ff 00 00 c1 e9 10 03 c8 8b c1 c1 e8 10 03 c1 f7 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule DDoS_Win32_Nitol_A_2147681432_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.gen!A"
        threat_id = "2147681432"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 85 bc fc ff ff 47 b0 65 88 85 bd fc ff ff c6 85 be fc ff ff 74 c6 85 bf fc ff ff 4d c6 85 c0 fc ff ff 6f c6 85 c1 fc ff ff 64 c6 85 c2 fc ff ff 75 b1 6c}  //weight: 2, accuracy: High
        $x_1_2 = {83 c4 04 83 c0 61 50 6a 1a e8}  //weight: 1, accuracy: High
        $x_1_3 = {25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 75 20 4d 42 [0-4] 25 75 20 4d 48 7a [0-4] 7e 4d 48 7a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Win32_Nitol_G_2147691772_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.G"
        threat_id = "2147691772"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 6f 77 21 20 42 61 64 20 68 6f 73 74 20 6c 6f 6f 6b 75 70 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 6f 73 74 20 6e 61 6d 65 20 69 73 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 64 64 72 65 73 73 20 25 64 20 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {33 d2 8a 11 03 c2 8b c8 25 ff ff 00 00 c1 e9 10 03 c8 8b c1 c1 e8 10 03 c1 f7 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Win32_Nitol_H_2147691913_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.H"
        threat_id = "2147691913"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 18 ff d7 bb 02 01 00 00 eb 28 ff d6 3b 44 24 10 72 2d 2b 44 24 10 3d 00 dd 6d 00 77 22 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {e9 1b 01 00 00 56 8b 35 ?? ?? ?? ?? 57 8b 7d 08 8d 85 e8 fb ff ff 81 ff 00 01 00 00 73 11 68}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d3 85 c0 75 42 83 bd b4 f9 ff ff 00 75 39 81 bd b8 f9 ff ff 00 00 20 03 73 2d}  //weight: 1, accuracy: High
        $x_1_4 = "s\" a -r -ep1\"%s\" \"%s\" \"%s\\lpk.dll\"" wide //weight: 1
        $x_1_5 = "cmd /c %s vb \"%s\" lpk.dll|find /i \"lpk.dll\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DDoS_Win32_Nitol_I_2147696328_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.I"
        threat_id = "2147696328"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e c6 84 24 ?? 00 00 00 65 c6 84 24 ?? 00 00 00 78 c6 84 24 ?? 00 00 00 65 c6 84 24 ?? 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 fc 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e6}  //weight: 1, accuracy: Low
        $x_1_3 = "tr0j4n" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Win32_Nitol_J_2147705502_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.J"
        threat_id = "2147705502"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 64 2e 25 64 2e 25 64 2e 25 64 00}  //weight: 1, accuracy: High
        $x_2_2 = "DNSFlood" ascii //weight: 2
        $x_1_3 = "192.168.1.244" ascii //weight: 1
        $x_2_4 = "jdfwkey" ascii //weight: 2
        $x_2_5 = {83 c0 03 33 d2 0f af c6 f7 74 24}  //weight: 2, accuracy: High
        $x_3_6 = "ddos.hackxk.com" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule DDoS_Win32_Nitol_K_2147706578_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.K"
        threat_id = "2147706578"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "jdfwkey" ascii //weight: 10
        $x_1_2 = {25 64 2e 25 64 2e 25 64 2e 25 64 00}  //weight: 1, accuracy: High
        $x_2_3 = {83 c0 03 33 d2 0f af c6 f7 74 24}  //weight: 2, accuracy: High
        $x_3_4 = "33921035.f3322.org" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule DDoS_Win32_Nitol_M_2147719006_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.M!bit"
        threat_id = "2147719006"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%c%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_2 = "/c @ping -n 5 127.0.0.1&del" ascii //weight: 1
        $x_1_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 00 00 44 65 73 63 72 69 70 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d 08 8a 14 11 32 94 45 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 ?? ?? ?? ?? 8b 4d 08 88 14 01 66 8b 55 fc 66 83 c2 01 66 89 55 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Win32_Nitol_L_2147719154_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.L!bit"
        threat_id = "2147719154"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 6f 77 21 20 42 61 64 20 68 6f 73 74 20 6c 6f 6f 6b 75 70 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 6f 73 74 20 6e 61 6d 65 20 69 73 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 64 64 72 65 73 73 20 25 64 20 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 00 00 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 00 00 00 00 44 65 73 63 72 69 70 74 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Win32_Nitol_L_2147720040_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.L"
        threat_id = "2147720040"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "^&*.htmGET ^&&%$" ascii //weight: 2
        $x_1_2 = "Referer: http://%s" ascii //weight: 1
        $x_1_3 = "Host: %s:%d" ascii //weight: 1
        $x_2_4 = "%c%c%c%c%c.exe" ascii //weight: 2
        $x_1_5 = "WinAddress123" ascii //weight: 1
        $x_1_6 = "qazwsxedc" ascii //weight: 1
        $x_1_7 = {00 32 30 31 35 2d 31 30 00}  //weight: 1, accuracy: High
        $x_1_8 = " | CORE %u" ascii //weight: 1
        $x_2_9 = {25 73 20 25 73 25 73 [0-4] 47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31}  //weight: 2, accuracy: Low
        $x_1_10 = {f7 d1 8d 44 24 ?? 49 50 8b d9 e8 ?? ?? ff ff 8b 8c 24 ?? ?? 00 00 83 c4 0c 89 44 24}  //weight: 1, accuracy: Low
        $x_1_11 = {55 ff d3 8b c7 b9 0a 00 00 00 99 f7 f9 85 d2 75 08 6a 05 ff 15 ?? ?? ?? ?? 47 81 ff e8 03 00 00 7c cc}  //weight: 1, accuracy: Low
        $x_2_12 = {66 c7 44 24 12 00 02 c6 44 24 0c 08 ff 15 ?? ?? ?? ?? 8b 4c 24 0c 8b 54 24 10 6a 1a 89 4c 24 50 89 54 24 54 89 44 24 58 e8 ?? ?? ?? ?? 83 c0 61}  //weight: 2, accuracy: Low
        $x_2_13 = {4a 74 06 c6 04 3e 78 eb ?? ff d3}  //weight: 2, accuracy: Low
        $x_2_14 = {68 01 10 00 00 33 f6 68 ff ff 00 00 53 89 74 24 ?? ff 15 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 6a 35 66 c7 44 24 ?? 02 00 ff d5}  //weight: 2, accuracy: Low
        $x_2_15 = {83 f8 7a 75 ?? 68 00 80 00 00 6a 00 57 ff 15 ?? ?? ?? ?? 6a 04 68 00 30 00 00 8b 44 24 ?? 83 c0 02 50}  //weight: 2, accuracy: Low
        $x_1_16 = {8a 4c 04 1c 80 f1 ?? 88 8c 04 ?? ?? 00 00 40 83 f8 10 72 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule DDoS_Win32_Nitol_L_2147720041_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.L!!Nitol.gen!A"
        threat_id = "2147720041"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "Nitol: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "^&*.htmGET ^&&%$" ascii //weight: 2
        $x_1_2 = "Referer: http://%s" ascii //weight: 1
        $x_1_3 = "Host: %s:%d" ascii //weight: 1
        $x_2_4 = "%c%c%c%c%c.exe" ascii //weight: 2
        $x_1_5 = "WinAddress123" ascii //weight: 1
        $x_1_6 = "qazwsxedc" ascii //weight: 1
        $x_1_7 = {00 32 30 31 35 2d 31 30 00}  //weight: 1, accuracy: High
        $x_1_8 = " | CORE %u" ascii //weight: 1
        $x_2_9 = {25 73 20 25 73 25 73 [0-4] 47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31}  //weight: 2, accuracy: Low
        $x_1_10 = {f7 d1 8d 44 24 ?? 49 50 8b d9 e8 ?? ?? ff ff 8b 8c 24 ?? ?? 00 00 83 c4 0c 89 44 24}  //weight: 1, accuracy: Low
        $x_1_11 = {55 ff d3 8b c7 b9 0a 00 00 00 99 f7 f9 85 d2 75 08 6a 05 ff 15 ?? ?? ?? ?? 47 81 ff e8 03 00 00 7c cc}  //weight: 1, accuracy: Low
        $x_2_12 = {66 c7 44 24 12 00 02 c6 44 24 0c 08 ff 15 ?? ?? ?? ?? 8b 4c 24 0c 8b 54 24 10 6a 1a 89 4c 24 50 89 54 24 54 89 44 24 58 e8 ?? ?? ?? ?? 83 c0 61}  //weight: 2, accuracy: Low
        $x_2_13 = {4a 74 06 c6 04 3e 78 eb ?? ff d3}  //weight: 2, accuracy: Low
        $x_2_14 = {68 01 10 00 00 33 f6 68 ff ff 00 00 53 89 74 24 ?? ff 15 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 6a 35 66 c7 44 24 ?? 02 00 ff d5}  //weight: 2, accuracy: Low
        $x_2_15 = {83 f8 7a 75 ?? 68 00 80 00 00 6a 00 57 ff 15 ?? ?? ?? ?? 6a 04 68 00 30 00 00 8b 44 24 ?? 83 c0 02 50}  //weight: 2, accuracy: Low
        $x_1_16 = {8a 4c 04 1c 80 f1 ?? 88 8c 04 ?? ?? 00 00 40 83 f8 10 72 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule DDoS_Win32_Nitol_N_2147722552_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.N!bit"
        threat_id = "2147722552"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 6f 77 21 20 42 61 64 20 68 6f 73 74 20 6c 6f 6f 6b 75 70 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 6f 73 74 20 6e 61 6d 65 20 69 73 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 64 64 72 65 73 73 20 25 64 20 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = {0f b6 0c 85 ?? ?? ?? ?? 28 4c 05 e8 0f b6 14 85 ?? ?? ?? ?? 0f b6 0c 85 ?? ?? ?? ?? 28 54 05 e9 28 4c 05 ea 0f b6 14 85 ?? ?? ?? ?? 0f b6 0c 85 ?? ?? ?? ?? 28 54 05 eb 28 4c 05 ec 83 c0 05 83 f8 14 7c bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Win32_Nitol_P_2147725201_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.P!bit"
        threat_id = "2147725201"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 64 64 6f 73 2e 74 66 00}  //weight: 10, accuracy: High
        $x_1_2 = {00 68 72 61 25 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_4 = {00 25 64 2e 25 64 2e 25 64 2e 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "Windows Help System Myss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Win32_Nitol_Q_2147725590_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Nitol.Q!bit"
        threat_id = "2147725590"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 03 33 d2 0f af c6 f7 74 24}  //weight: 1, accuracy: High
        $x_1_2 = {25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_4 = "ddos.tf" ascii //weight: 1
        $x_1_5 = "192.168.1.244" ascii //weight: 1
        $x_1_6 = "Referer: http://%s%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


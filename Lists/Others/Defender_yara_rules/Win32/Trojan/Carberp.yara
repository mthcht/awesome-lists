rule Trojan_Win32_Carberp_I_2147648222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.I"
        threat_id = "2147648222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 0a 03 00 66 c7 45 08 01 00 14 00 eb 25 (6a 04 8d|8d 45 08) 50 68 80 00 00 00 68 ff ff 00 00 57 66}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f8 63 [0-8] 66 c7 45 fb 03 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 89 75 f7 c6 45 f4 73 66 89 45 f5}  //weight: 1, accuracy: High
        $x_1_4 = {66 89 95 ab f9 ff ff c6 85 a8 f9 ff ff 73 66 8b 45 ?? 66 89 85 a9 f9 ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = "s&statpass=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Carberp_I_2147648222_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.I"
        threat_id = "2147648222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 65 50 72 c7 84 24 ?? ?? ?? ?? 43 72 65 61 c6 84 24}  //weight: 1, accuracy: Low
        $x_1_2 = {74 69 6f 6e c7 84 24 ?? ?? ?? ?? 66 53 65 63 c7 84 24}  //weight: 1, accuracy: Low
        $x_1_3 = {45 78 00 00 c7 84 24 ?? ?? ?? ?? 6c 6c 6f 63 c7 84 24 ?? ?? ?? ?? 75 61 6c 41 c7 84 24}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 65 6d 6f c7 84 24 ?? ?? ?? ?? 63 65 73 73 c7 84 24 ?? ?? ?? ?? 65 50 72 6f}  //weight: 1, accuracy: Low
        $x_1_5 = {68 72 65 61 c7 84 24 ?? ?? ?? ?? 47 65 74 54 c6 84 24}  //weight: 1, accuracy: Low
        $x_1_6 = {79 00 00 00 c7 84 24 ?? ?? ?? ?? 65 6d 6f 72 c7 84 24 ?? ?? ?? ?? 65 73 73 4d}  //weight: 1, accuracy: Low
        $x_1_7 = {74 65 78 74 c7 84 24 ?? ?? ?? ?? 64 43 6f 6e c7 84 24 ?? ?? ?? ?? 68 72 65 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Carberp_I_2147648222_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.I"
        threat_id = "2147648222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "server-%s.googlesearchreport.com:" ascii //weight: 4
        $x_4_2 = "/stat?uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s" ascii //weight: 4
        $x_1_3 = "&guid=%s&comment=%s&p=%d&s=%s" ascii //weight: 1
        $x_2_4 = "Mp6c3Ygukx29GbDk_exit" ascii //weight: 2
        $x_2_5 = {83 c3 03 c6 43 fd 25 88 d0 c0 e8 04 0f b6 c0 8a 80}  //weight: 2, accuracy: High
        $x_1_6 = "server-%s.o12955reps.com:" ascii //weight: 1
        $x_1_7 = ",server-%s.updmaker.com:" ascii //weight: 1
        $x_1_8 = "server-%s.gglerr.com:" ascii //weight: 1
        $x_1_9 = "%s.toolgot.com:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Carberp_B_2147681817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.gen!B"
        threat_id = "2147681817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 39 36 75 04 8b c1 eb 09 c6 00 36 c6 40 01 34}  //weight: 1, accuracy: High
        $x_1_2 = {66 3d 46 4a 74 0d 83 c6 ?? 0f b7 06 66 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {66 81 78 04 64 86 75 08 8b 80 88 00 00 00 eb 03 8b 40 78}  //weight: 1, accuracy: High
        $x_1_4 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca}  //weight: 1, accuracy: High
        $x_1_5 = {56 6e 63 44 4c 4c 2e 64 6c 6c 00 56 6e 63 53 72 76 57 6e 64 50 72 6f 63 00 56 6e 63 53 74 61 72 74 53 65 72 76 65 72 00 56 6e 63 53 74 6f 70 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Carberp_K_2147707001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.K"
        threat_id = "2147707001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 03 66 c7 00 eb f9}  //weight: 1, accuracy: High
        $x_1_2 = {3a c3 3c bd 75}  //weight: 1, accuracy: High
        $x_1_3 = {8f fa 0d 25 74}  //weight: 1, accuracy: High
        $x_1_4 = {b9 42 4d 00 00 66 89 4d}  //weight: 1, accuracy: High
        $x_1_5 = "log=1&id=%ls&name=%ls&type=p&text=%ls" wide //weight: 1
        $x_1_6 = "plugin=1&desc=%s&id=%ls&name=%ls&text=%s" ascii //weight: 1
        $x_1_7 = {25 73 6c 6f 67 73 2e 63 61 62 00}  //weight: 1, accuracy: High
        $x_1_8 = "%ls\\%d%d.%ls" wide //weight: 1
        $x_1_9 = "cmd=1&id=%ls&name=%ls&os=%ls&p=%i&av=%ls&v=%ls&w=%i" wide //weight: 1
        $x_1_10 = "exec=1&task_id=%S" wide //weight: 1
        $x_1_11 = "fail=1&task_id=%S" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Carberp_BW_2147718201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.BW!bit"
        threat_id = "2147718201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\Mp6c3Ygukx29GbDk_exit" wide //weight: 1
        $x_2_2 = "Global\\{DE5F5682-D0A1-4B29-B5DB-47298A44880C}" wide //weight: 2
        $x_1_3 = "SOFTWARE\\VDI\\Shared\\Product Updater\\GUID" wide //weight: 1
        $x_2_4 = ":30,server-%s." wide //weight: 2
        $x_1_5 = {77 69 6e 00 2c 73 65 72 76 65 72 00 2c 78 36 34 [0-4] 2c 78 38 36 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Carberp_BX_2147718546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.BX!bit"
        threat_id = "2147718546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Global\\Mp6c3Ygukx29GbDk_exit" wide //weight: 2
        $x_2_2 = {77 69 6e 00 2c 73 65 72 76 65 72 00 2c 78 36 34 [0-4] 2c 78 38 36 00}  //weight: 2, accuracy: Low
        $x_1_3 = "produpd.exe" wide //weight: 1
        $x_1_4 = "monhost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Carberp_BY_2147718560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.BY!bit"
        threat_id = "2147718560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 28 8b 06 8a 0c 19 32 4c 04 10 88 0b 43 83 ed 01 75 ?? 0f 10 44 24 10 5f}  //weight: 2, accuracy: Low
        $x_1_2 = "http://www.yandex.ru" wide //weight: 1
        $x_1_3 = {00 73 65 72 76 65 72 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Carberp_BZ_2147720554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.BZ!bit"
        threat_id = "2147720554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Global\\Mp6c3Ygukx29GbDk_exit" wide //weight: 2
        $x_1_2 = {2e 3f 41 56 62 6f 74 6e 65 74 5f ?? 40 62 6f 74 40 40}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 3f 41 56 62 6f 74 6e 65 74 5f 68 6f 73 74 5f ?? 40 62 6f 74 40 40}  //weight: 1, accuracy: Low
        $x_2_4 = {3f 24 64 65 66 61 75 6c 74 5f 64 65 6c 65 74 65 40 56 3f 24 74 75 70 6c 65 40 [0-16] 40 62 6f 74}  //weight: 2, accuracy: Low
        $x_1_5 = "produpd.exe" wide //weight: 1
        $x_1_6 = "monhost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Carberp_GHG_2147847764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carberp.GHG!MTB"
        threat_id = "2147847764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 0f be 82 ?? ?? ?? ?? 8b 4d fc 83 c1 01 81 f1 89 00 00 00 2b c1 8b 55 fc 88 82 ?? ?? ?? ?? 8b 45 fc 83 c0 01 89 45 fc e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


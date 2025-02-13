rule TrojanDownloader_Win32_Kuluoz_A_172580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kuluoz.A"
        threat_id = "172580"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 00 8d 4d 00 51 8b 55 ?? 52 ff 55}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 40 01 68 8b 8d ?? ?? ff ff 03 8d ?? ?? ff ff 8b 55 ?? 89 51 02 8b 85 00 ff ff 03 85 01 ff ff c6 40 06 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Kuluoz_B_173812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kuluoz.B"
        threat_id = "173812"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_2 = "/index.php?r=gate&id=" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = {26 67 72 6f 75 70 3d 00 26 64 65 62 75 67 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 69 64 6c 00 72 75 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Kuluoz_B_173812_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kuluoz.B"
        threat_id = "173812"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 51 24 03 55 ?? 89 55 ?? c6 45 ?? 57 c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 6b c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 42 24 03 85 ?? ?? ff ff 89 85 ?? ?? ff ff c6 85 ?? ?? ff ff 57 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 72 c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 42 01 68 8b 45 ?? 03 85 ?? ?? ff ff 8b 4d ?? 89 48 02 8b 55 00 03 95 01 ff ff c6 42 06 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 40 01 68 8b 4d ?? 03 8d ?? ?? ff ff 8b 55 ?? 89 51 02 8b 45 ?? 03 85 ?? ?? ff ff c6 40 06 c3}  //weight: 1, accuracy: Low
        $x_10_5 = ".php?r=gate&id=" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Kuluoz_C_174849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kuluoz.C"
        threat_id = "174849"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&r=%1024[^&]&a=%x&k=%x&n=%1024s" ascii //weight: 1
        $x_1_2 = "c=upd&r=%1024s" ascii //weight: 1
        $x_1_3 = "%1024[^=]=%1024[^;]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Kuluoz_C_174849_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kuluoz.C"
        threat_id = "174849"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c=rdl&u=%1024[^&]&a=%x&k=%x&n=%1024s" ascii //weight: 1
        $x_1_2 = "c=run&u=%1024s" ascii //weight: 1
        $x_1_3 = "%1024[^=]=%1024[^;]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Kuluoz_D_174869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kuluoz.D"
        threat_id = "174869"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 40 01 68 8b 4d ?? 03 8d ?? ?? ff ff 8b 55 ?? 89 51 02 8b 45 ?? 03 85 ?? ?? ff ff c6 40 06 c3}  //weight: 2, accuracy: Low
        $x_2_2 = "<knock><id>%s</id>" ascii //weight: 2
        $x_1_3 = "http://%[^:]:%d/%s" ascii //weight: 1
        $x_1_4 = "%1024[^=]=%1024[^;]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Kuluoz_D_205760_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kuluoz.D!!Kuluoz.gen!A"
        threat_id = "205760"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        info = "Kuluoz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 40 01 68 8b 4d ?? 03 8d ?? ?? ff ff 8b 55 ?? 89 51 02 8b 45 ?? 03 85 ?? ?? ff ff c6 40 06 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "<knock><id>%s</id>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


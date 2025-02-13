rule TrojanDownloader_Win32_Silcon_C_2147720093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Silcon.C!bit"
        threat_id = "2147720093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Silcon"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe c2 02 1c 16 8a 04 16 8a 2c 1e 88 04 1e 88 2c 16 00 e8 47 8a 04 06 30 07 ff 4d 0c 75 e2}  //weight: 2, accuracy: High
        $x_1_2 = {32 06 46 88 07 8b 5d f4 8b 4d f8 89 ca 83 e1 03}  //weight: 1, accuracy: High
        $x_1_3 = {89 c3 8b 07 8b 4f 04 89 c7 89 c8 31 d2 f7 f6 97 f7 f6 29 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Silcon_D_2147722706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Silcon.D!bit"
        threat_id = "2147722706"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Silcon"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad c1 c0 04 c1 c0 01 2b 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? ab 81 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff d0 50 8f 05 ?? ?? ?? ?? c3 20 00 52 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 40 b9 ?? ?? ?? ?? 51 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Silcon_E_2147722712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Silcon.E!bit"
        threat_id = "2147722712"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Silcon"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 c0 04 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? ab 81 fe ?? ?? ?? ?? 7c 0d 00 ad 33 05 ?? ?? ?? ?? 03 05}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff d0 50 8f 05 ?? ?? ?? ?? c3 24 00 52 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? be ?? ?? ?? ?? 56 b9 ?? ?? ?? ?? 51 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


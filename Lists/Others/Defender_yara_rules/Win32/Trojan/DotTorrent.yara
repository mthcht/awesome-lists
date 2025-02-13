rule Trojan_Win32_DotTorrent_149018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DotTorrent"
        threat_id = "149018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DotTorrent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4d 61 6e 61 67 65 72 00 44 6f 77 6e 6c 6f 61 64 20 41 ?? 4d 61 6e 61 67 65 72 00 ?? ?? ?? 5c 61 ?? 6d 61 6e 61 67 65 72 2e 65 78 65 00}  //weight: 10, accuracy: Low
        $x_1_2 = {73 6f 66 74 2f 69 6e 73 74 61 6c 6c 2d 03 00 2f 6d 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 74 6f 72 72 65 6e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DotTorrent_149018_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DotTorrent"
        threat_id = "149018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DotTorrent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6d 00 35 00 73 00 65 00 63 00 75 00 72 00 65 00 2f 00 [0-21] (69 00 6e 00 64 00 65 00|72 00 65 00 66 00 75 00 73 00 61 00) 2e 00 70 00 68 00 70 00}  //weight: 5, accuracy: Low
        $x_5_2 = {6d 00 35 00 73 00 65 00 63 00 75 00 72 00 65 00 2f 00 [0-21] 78 00 65 00 64 00 6e 00 69 00 [0-21] 2e 00 70 00 68 00 70 00}  //weight: 5, accuracy: Low
        $x_1_3 = {2a 00 2e 00 74 00 6f 00 72 00 72 00 65 00 6e 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 00 66 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 00 2d 00 51 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DotTorrent_149018_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DotTorrent"
        threat_id = "149018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DotTorrent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4d 61 6e 61 67 65 72 00 49 6e 73 74 61 6c 6c 00 ?? ?? ?? ?? 77 61 6c 6c 70 61 70 65 72 2e 6a 70 67 00 61 70 6d 61 6e 61 67 65 72 2e 65 78 65 00 73 65 74 74 69 6e 67 73 2e 69 6e 69}  //weight: 10, accuracy: Low
        $x_5_2 = {4d 61 6e 61 67 65 72 00 49 6e 73 74 61 6c 6c 00 ?? ?? ?? ?? ?? ?? 6d 61 6e 61 67 65 72 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_5_3 = {77 61 6c 6c 70 61 70 65 72 2e 6a 70 67 00 73 65 74 74 69 6e 67 73 2e 69 6e 69 00}  //weight: 5, accuracy: High
        $x_5_4 = {73 65 74 74 69 6e 67 73 2e 69 6e 69 00 77 61 6c 6c 70 61 70 65 72 2e 6a 70 67 00}  //weight: 5, accuracy: High
        $x_1_5 = "Uninstall\\IQManager" ascii //weight: 1
        $x_1_6 = "I-Q Manager.lnk" ascii //weight: 1
        $x_1_7 = "Uninstall\\APManager" ascii //weight: 1
        $x_1_8 = "AP Manager.lnk" ascii //weight: 1
        $x_1_9 = "Uninstall\\ARManager" ascii //weight: 1
        $x_1_10 = "ARManager.lnk" ascii //weight: 1
        $x_1_11 = {55 6e 69 6e 73 74 61 6c 6c 5c 41 [0-3] 4d 61 6e 61 67 65 72}  //weight: 1, accuracy: Low
        $x_1_12 = {4d 61 6e 61 67 65 72 2e 6c 6e 6b 02 00 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}


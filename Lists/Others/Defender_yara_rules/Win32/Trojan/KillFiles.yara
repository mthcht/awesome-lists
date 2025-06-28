rule Trojan_Win32_KillFiles_AN_2147818986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillFiles.AN!MTB"
        threat_id = "2147818986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillFiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LblWin" ascii //weight: 1
        $x_1_2 = "You've filled the list box. Abandoning search" wide //weight: 1
        $x_1_3 = "win.ini" wide //weight: 1
        $x_1_4 = "Dir1_Change" ascii //weight: 1
        $x_1_5 = "Drive1_Change" ascii //weight: 1
        $x_1_6 = "File1_Click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillFiles_RP_2147906276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillFiles.RP!MTB"
        threat_id = "2147906276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillFiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ca c0 c9 60 f6 da 66 c1 c1 c1 d0 ca 66 d3 c9 f9 80 f2 02 32 da 66 0b cf 32 c8 66 8b 0c 14 66 0f ba e2 c1}  //weight: 1, accuracy: High
        $x_10_2 = {55 52 0f b7 ed 8b 74 24 14 c7 44 24 14 ?? ?? ?? ?? 81 44 24 04 ?? ?? ?? ?? 66 f7 dd 66 2b 6c 24 05 e8 ?? ?? ?? ?? f7 d0 e9 ?? ?? ?? ?? fe c0 f8 32 d8 66 89 14 04 c0 c4 34 66 0f ba f0 74 e9}  //weight: 10, accuracy: Low
        $x_1_3 = {f9 81 ed 02 00 00 00 f9 66 89 4c 25 00 66 81 c9 58 28 8b 0e 81 c6 04 00 00 00 f5 33 cb d1 c9 f6 c1 82 3b f2 85 c4 81 c1 ?? ?? ?? ?? d1 c9 f8 f5 81 f1 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_10_4 = {8b 0e 66 41 d3 db 66 45 8b 5e 08 40 f6 d7 44 0f ab ef 49 81 c6 0a 00 00 00 36 66 45 89 19 40 80 ef 2d f5 48 81 ee 04 00 00 00 48 0f b7 ff 8b 3e f7 c1 ?? ?? ?? ?? 45 3a f8 41 33 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KillFiles_CCIN_2147924340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillFiles.CCIN!MTB"
        threat_id = "2147924340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillFiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8d 0c 3e 8b c6 46 f7 75 f4 8a 82 ?? ?? ?? ?? 8b 55 fc 32 04 0a 88 01 3b f3 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KillFiles_TMX_2147944947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillFiles.TMX!MTB"
        threat_id = "2147944947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillFiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 06 8d 41 01 fe c9 80 e2 01 0f b6 c0 0f b6 c9 0f 45 c8 8b 45 e4 88 0c 06 46 3b f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


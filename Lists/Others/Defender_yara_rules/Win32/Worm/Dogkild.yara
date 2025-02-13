rule Worm_Win32_Dogkild_A_2147626198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dogkild.A!dll"
        threat_id = "2147626198"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\drivers\\pcidump.sys" ascii //weight: 1
        $x_1_2 = {56 53 4d 45 70 78 6f 6d 70 62 65 55 70 44 62 64 69 66 47 6a 6d 66 42 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 6a 08 8d 45 ?? 50 68 14 20 22 00 ff 75 f4 ff 15 ?? ?? ?? ?? 68 d0 07 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dogkild_B_2147628789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dogkild.B"
        threat_id = "2147628789"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 75 0d 8d 44 24 08 50 e8 ?? ?? ff ff 83 c4 04 fe c3 80 fb 7a 7e c7}  //weight: 1, accuracy: Low
        $x_1_2 = {68 c8 00 00 00 51 68 0c 20 22 00 53 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Dogkild_C_2147629581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dogkild.C"
        threat_id = "2147629581"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b f0 c1 ee 19 c1 e0 07 0b f0 0f be c1 8a 4a 01 33 c6 42 84 c9 75 e9}  //weight: 3, accuracy: High
        $x_3_2 = {73 14 8b 45 fc 03 45 f8 8a 00 2c 01 8b 4d fc 03 4d f8 88 01 eb}  //weight: 3, accuracy: High
        $x_1_3 = {68 14 20 22 00}  //weight: 1, accuracy: High
        $x_3_4 = {83 ff 31 7e 05 83 ef 32 eb 03 83 c7 0a}  //weight: 3, accuracy: High
        $x_1_5 = {5c 5c 2e 5c 70 63 69 64 75 6d 70 00}  //weight: 1, accuracy: High
        $x_1_6 = "\\drivers\\AsyncMac.sys" ascii //weight: 1
        $x_1_7 = "taskkill.exe /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dogkild_D_2147631460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dogkild.D"
        threat_id = "2147631460"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 e0 01 00 00 68 80 02 00 00 6a 64 6a 64 68 00 00 cf 00}  //weight: 2, accuracy: High
        $x_2_2 = {83 f8 03 74 0c 8d 54 24 08 52 ff d6 83 f8 02 75 0d}  //weight: 2, accuracy: High
        $x_1_3 = "/im egui.exe /f" ascii //weight: 1
        $x_1_4 = "delete RsRavMon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


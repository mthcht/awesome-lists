rule Trojan_Win32_Fsblock_A_2147669242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsblock.A"
        threat_id = "2147669242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsblock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BITBTN1_BITMAP" ascii //weight: 1
        $x_1_2 = {e1 eb ee ea e8 f0 ee e2}  //weight: 1, accuracy: High
        $x_1_3 = {6f 70 3d cc d2 d1 3b ?? ?? 3b 6e 75 6d 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fsblock_A_2147669242_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsblock.A"
        threat_id = "2147669242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsblock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e1 eb ee ea e8 f0 ee e2}  //weight: 1, accuracy: High
        $x_1_2 = "taskmgr.exe, msconfig.exe, regedit.exe, cmd.exe" ascii //weight: 1
        $x_1_3 = {70 69 6e 67 20 20 31 32 37 2e 30 2e 30 2e 31 [0-10] 64 65 6c [0-16] 64 65 6c 20 25 30 [0-5] 2e 62 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fsblock_A_2147669242_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsblock.A"
        threat_id = "2147669242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsblock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "taskmgr.exe, msconfig.exe, regedit.exe, cmd.exe" ascii //weight: 1
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 5c 4f 6c 65 20 44 42 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v" ascii //weight: 1
        $x_2_4 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools /t reg_dword /d 1 -y" ascii //weight: 2
        $x_2_5 = {63 6f 70 79 20 [0-8] 2e 65 78 65 20 22 25 50 72 6f 67 72 61 6d 44 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c [0-8] 2e 65 78 65 22 20 2d 79}  //weight: 2, accuracy: Low
        $x_1_6 = {6d 72 62 65 6c 79 61 73 68 6e 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


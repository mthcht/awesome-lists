rule TrojanSpy_Win32_Talsab_A_2147637346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Talsab.A"
        threat_id = "2147637346"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff}  //weight: 6, accuracy: High
        $x_1_2 = {69 63 65 72 69 6b 3d 00 [0-16] 50 4f 53 54 20 2f 31 73 74 65 6d 61 69 6c 2e 70 68 70 20 48 54 54 50 2f 31 2e 31}  //weight: 1, accuracy: Low
        $x_1_3 = {75 73 65 72 3d 00 [0-16] 64 65 73 74 69 6e 6f 3d 00 [0-16] 26 63 6f 6e 74 65 75 64 6f 3d 00 [0-16] 68 74 74 70 3a 2f 2f 77 77 77 2e 00 [0-16] 2e 69 6e 66 6f 2f 31 73 74 65 6d 61 69 6c 2e 70 68 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 63 6f 6e 74 65 75 64 6f 3d 00 [0-16] 50 4f 53 54 20 2f 31 73 74 65 6d 61 69 6c 2e 70 68 70 20 48 54 54 50 2f 31 2e 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Talsab_B_2147641488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Talsab.B"
        threat_id = "2147641488"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff}  //weight: 2, accuracy: High
        $x_1_2 = "avp.exe" ascii //weight: 1
        $x_1_3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_2_4 = "sifreli2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Talsab_C_2147648043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Talsab.C"
        threat_id = "2147648043"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://www.31334.info/1stemail.php" ascii //weight: 4
        $x_3_2 = "cmd /c REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V rundll /D \"\\\"" ascii //weight: 3
        $x_2_3 = "&conteudo=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


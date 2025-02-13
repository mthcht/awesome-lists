rule TrojanSpy_Win32_Banload_ZEK_2147689283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banload.ZEK"
        threat_id = "2147689283"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 42 41 43 4b 53 50 41 43 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {08 43 41 50 53 4c 4f 43 4b 00}  //weight: 1, accuracy: High
        $x_1_3 = {06 45 53 43 41 50 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {0a 53 43 52 4f 4c 4c 4c 4f 43 4b 00}  //weight: 1, accuracy: High
        $x_1_5 = {06 44 45 4c 45 54 45 00}  //weight: 1, accuracy: High
        $x_1_6 = {05 45 4e 54 45 52 00}  //weight: 1, accuracy: High
        $x_1_7 = {04 48 4f 4d 45 00}  //weight: 1, accuracy: High
        $x_1_8 = {41 74 75 61 6c 69 7a 61 c3 a7 c3 a3 6f 20 64 65 20 53 65 67 75 72 61 6e c3 a7 61 20 2d 20 48 53 42 43 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banload_AAA_2147729975_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banload.AAA!bit"
        threat_id = "2147729975"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4b 85 db 7c ?? 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
        $x_1_3 = "%WINDIR%\\system32\\timeout.exe 3 & del" wide //weight: 1
        $x_1_4 = "%TEMP%\\curbuf.dat" wide //weight: 1
        $x_1_5 = "UHJvY2Vzc29yTmFtZVN0cmluZw==" ascii //weight: 1
        $x_1_6 = "RGlzcGxheVZlcnNpb24=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


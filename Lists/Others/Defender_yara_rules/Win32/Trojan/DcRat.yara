rule Trojan_Win32_DcRat_GFE_2147841672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DcRat.GFE!MTB"
        threat_id = "2147841672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 32 57 56 e8 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 83 c6 01 83 d7 00 75 ?? 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 55 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DcRat_CAD_2147842013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DcRat.CAD!MTB"
        threat_id = "2147842013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c powershell -Command Add-MpPreference -ExclusionPath \"C:\\Users\\Public" ascii //weight: 1
        $x_1_2 = "cmd.exe /c powershell -Command Add-MpPreference -ExclusionProcess \"C:\\Users\\Public\\readme.exe" ascii //weight: 1
        $x_1_3 = "cmd.exe /c powershell \"C:\\Users\\Public\\readme.exe" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" wide //weight: 1
        $x_1_6 = "AnyDesk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DcRat_CB_2147848047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DcRat.CB!MTB"
        threat_id = "2147848047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "raw.githubusercontent.com/NewAccount2021/halka/main/manafa" wide //weight: 1
        $x_1_2 = "51.79.49.73/crc/ex.bat" wide //weight: 1
        $x_1_3 = "51.79.49.73/crc/printui.exe" wide //weight: 1
        $x_1_4 = "Skin Readme.txt" wide //weight: 1
        $x_1_5 = "I'm sorry Dave but I can't let you do that until I reach version" wide //weight: 1
        $x_1_6 = "{ENTER}" wide //weight: 1
        $x_1_7 = "{TAB}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DcRat_DA_2147851788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DcRat.DA!MTB"
        threat_id = "2147851788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 e3 2c ae cc 59 1c ee e1 0e 9c 8b ab 2d d0 1b db 1c 36 d3 3e 56 ee a6 d5 f1 1f b9 5f fc fd d2 30 92 72 f9 d8 ba 78}  //weight: 1, accuracy: High
        $x_1_2 = {d1 ef bc 69 e9 e5 b7 99 35 6a b1 18 46 9c 21 0c 96 35 86 5f 90 21 11 f3}  //weight: 1, accuracy: High
        $x_1_3 = {87 75 59 65 33 7b c5 64 a4 4a 43 a1 95 e3 c8 f7 bc 89 5a de 84 44 57 3a a8 04 ad 06 ce 6e a9 4d 23 bd 15 47 0f 65 5d 96 6f ed 0f 2b fa ff 00 30 6a 76 3d dc bb b1 9f 19 f5 e0}  //weight: 1, accuracy: High
        $x_1_4 = {69 d4 78 ae 28 f1 af 07 b7 60 f6 2c 3e 85 98 7c 3a b6 ef e7 3a 31 6c 32 a3 bb 1e e8 63 25 a7 6e cf 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win32_Wyhymyz_A_2147721501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wyhymyz.A"
        threat_id = "2147721501"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wyhymyz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UNIQUE_ID_DO_NOT_REMOVE" ascii //weight: 1
        $x_1_2 = "REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"allkeeper\" /t REG_SZ /d " ascii //weight: 1
        $x_1_3 = "HERMES" ascii //weight: 1
        $x_1_4 = "JDSkfngrjtby5ntoivtmovrkmekvmclkvcvtrgbybtdklfevlkbrlevr" ascii //weight: 1
        $x_1_5 = "DECRYPT_INFORMATION.html" ascii //weight: 1
        $x_2_6 = "del /s /f /q c:\\*.VHD c:\\*.bac c:\\*.bak c:\\*.wbcat c:\\*.bkf c:\\Backup*.* c:\\backup*.* c:\\*.set c:\\*.win c:\\*.dsk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Wyhymyz_B_2147723688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wyhymyz.B"
        threat_id = "2147723688"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wyhymyz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {80 7d f4 48 [0-4] 80 7d f5 45 [0-4] 80 7d f6 52 [0-4] 80 7d f7 4d [0-4] 80 7d f8 45 [0-4] 80 7d f9 53}  //weight: 4, accuracy: Low
        $x_2_2 = "\\DECRYPT_INFORMATION.txt" ascii //weight: 2
        $x_1_3 = "MolVffQuDtUPlwTNeAEGoYwbZGILW" ascii //weight: 1
        $x_1_4 = {6a 01 68 10 66 00 00 ff ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = "shadowstorage vssadmin Delete vssadmin resize .dsk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Wyhymyz_C_2147724970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wyhymyz.C!bit"
        threat_id = "2147724970"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wyhymyz"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 68 10 66 00 00 ff ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {00 48 45 52 4d 45 53 00}  //weight: 1, accuracy: High
        $x_1_3 = "UNIQUE_ID_DO_NOT_REMOVE" wide //weight: 1
        $x_1_4 = "CRYPT_INFORMATION.html" wide //weight: 1
        $x_1_5 = {00 52 53 41 31 00 08 00 00 01 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Wyhymyz_D_2147725688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wyhymyz.D"
        threat_id = "2147725688"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wyhymyz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DECRYPT_INFORMATION.html" wide //weight: 1
        $x_2_2 = "UNIQUE_ID_DO_NOT_REMOVE" wide //weight: 2
        $x_4_3 = "del /s /f .wbcat f:\\*.bkf \\*.bac h:\\*.bak \\*.set h:\\*.win bkf h:\\Backup*.*ac f:\\*.bak f:\\*et f:\\*.win f:\\*:\\backup*.* g:\\*/q g:\\*.VHD g:\\*" ascii //weight: 4
        $x_4_4 = "/for=d: /on=d: storage /for=g: e shadowstorage vssadmin Delete vssadmin resize .dsk" ascii //weight: 4
        $x_8_5 = {8d a4 24 00 00 00 00 30 9e ?? ?? 40 00 46 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 04 3b f0 7c}  //weight: 8, accuracy: Low
        $x_8_6 = {66 0f 1f 84 00 00 00 00 00 30 9e ?? ?? 40 00 46 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 04 3b f0 7c}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}


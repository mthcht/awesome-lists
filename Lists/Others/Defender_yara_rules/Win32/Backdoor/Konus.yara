rule Backdoor_Win32_Konus_A_2147690861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Konus.A"
        threat_id = "2147690861"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Konus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4b 72 6f 6e 6f 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 64 61 74 61 5f 69 6e 6a 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 3c 7e 2a 23 2a 7e 3e 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 46 33 50 37 59 36 50 33 55 33 45 32 55 35 46 33 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 50 34 59 37 54 37 52 37 52 38 58 33 45 33 41 33 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 44 33 53 30 41 37 52 34 46 36 43 38 46 32 52 35 00}  //weight: 1, accuracy: High
        $x_1_7 = "%ws\\%ws.cfg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Konus_B_2147729779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Konus.B!bit"
        threat_id = "2147729779"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Konus"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 44 33 53 30 41 37 52 34 46 36 43 38 46 32 52 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 64 61 74 61 5f 69 6e 6a 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "{C415D88B-D9A4-4A53-9345-1E60887E85B1}\\wat.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


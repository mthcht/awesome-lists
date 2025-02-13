rule Worm_Win32_Esfury_A_2147634030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Esfury.A"
        threat_id = "2147634030"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Esfury"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2e 00 69 00 6e 00 66 00 6f 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "NVIDIA Media Center Library" wide //weight: 2
        $x_1_3 = {41 00 54 00 41 00 44 00 [0-10] 54 00 58 00 54 00 2e 00 4e 00 4f 00 49 00 53 00 52 00 45 00 56 00 [0-8] 2f 00 2f 00 3a 00 70 00 74 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_4 = "DrivesGuideInfo" wide //weight: 1
        $x_1_5 = "fni.nurotua" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Esfury_B_2147636502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Esfury.B"
        threat_id = "2147636502"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Esfury"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2d 00 30 00 2e 00 69 00 6e 00 66 00 6f 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "NVIDIA Media Center Library" wide //weight: 2
        $x_1_3 = {43 00 72 00 65 00 61 00 74 00 65 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 54 00 [0-4] 53 00 61 00 76 00 45 00}  //weight: 1, accuracy: Low
        $x_1_4 = "winlogon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Esfury_A_2147636744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Esfury.gen!A"
        threat_id = "2147636744"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Esfury"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 68 00 65 00 61 00 70 00 73 00 31 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "action=Abrir" wide //weight: 1
        $x_1_3 = "mSpread_Autorun" ascii //weight: 1
        $x_1_4 = "mSpread_Msn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Esfury_T_2147643154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Esfury.T"
        threat_id = "2147643154"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Esfury"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 11 fc 0d 0a ?? ?? ?? ?? 3c f5 00 00 00 00 f5 00 00 00 00 f4 00 fc 0d f4 56 fc 0d 0a ?? ?? ?? ?? 3c f5 00 00 00 00 f5 02 00 00 00 f4 00 fc 0d f4 56 fc 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 02 eb b3 fb e6 ea f4 01 eb c8 35 ?? ff 1c 92 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Esfury_V_2147660259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Esfury.V"
        threat_id = "2147660259"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Esfury"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 48 ff 01 00 6c 68 ff 6c 10 00 04 30 ff 0a 00 00 10 00 04 30 ff fd fe 2c ff 0b 01 00 04 00 f4 08 a9 e7 04 1c ff 0a 02 00 08 00 04 1c ff fb ef}  //weight: 5, accuracy: High
        $x_1_2 = "SYmlgjmfU" wide //weight: 1
        $x_1_3 = "Ymlgjmf&af^" wide //weight: 1
        $x_1_4 = "k`]ddTgh]f5Gh]f" wide //weight: 1
        $x_1_5 = "oaf`]dh+*&]p]" wide //weight: 1
        $x_1_6 = "N=JKAGF&LPL" wide //weight: 1
        $x_1_7 = "Tkqkl]e+*Tjmf\\dd+*&]p]" wide //weight: 1
        $x_1_8 = "<]kclgh&afa" wide //weight: 1
        $x_1_9 = "K%)%1%()%+/+11//,()%" wide //weight: 1
        $x_1_10 = "T;mjj]flN]jkagfTJmf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Esfury_X_2147661625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Esfury.X"
        threat_id = "2147661625"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Esfury"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 70 72 65 61 64 53 68 61 72 65 64 46 6f 6c 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "|_avp|_avp32|_avpcc" wide //weight: 1
        $x_1_3 = {00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 68 00 61 00 72 00 65 00 61 00 7a 00 61 00 5c 00 53 00 68 00 61 00 72 00 65 00 61 00 7a 00 61 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


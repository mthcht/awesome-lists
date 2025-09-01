rule Trojan_O97M_Obfuse_A_2147728825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.A"
        threat_id = "2147728825"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = CreateObject(StrReverse(" ascii //weight: 1
        $x_1_2 = " & StrReverse(StrReverse(StrReverse(StrReverse(" ascii //weight: 1
        $x_1_3 = " = 1 To Len(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_B_2147728845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.B"
        threat_id = "2147728845"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-10] 28 22 4d ?? ?? 69 ?? ?? 63 ?? ?? 72 ?? ?? 6f ?? ?? 73 ?? ?? 6f ?? ?? 66 ?? ?? 74 ?? ?? 2e ?? ?? 58 ?? ?? 4d ?? ?? 4c ?? ?? 48 ?? ?? 54 ?? ?? 54 ?? ?? 50 ?? ?? 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-10] 28 22 41 ?? ?? 44 ?? ?? 4f ?? ?? 44 ?? ?? 42 ?? ?? 2e ?? ?? 53 ?? ?? 74 ?? ?? 72 ?? ?? 65 ?? ?? 61 ?? ?? 6d ?? ?? 22 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_C_2147729237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.C"
        threat_id = "2147729237"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 6e 20 5f 0d 0a 45 72 72 6f 72 20 5f 0d 0a 52 65 73 75 6d 65 20 5f 0d 0a 4e 65 78 74 0d 0a 44 69 6d 20}  //weight: 1, accuracy: High
        $x_1_2 = "//^:^\" + \"p^tth@v" ascii //weight: 1
        $x_1_3 = ")) + Format(Chr(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_E_2147729561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.E"
        threat_id = "2147729561"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 41 73 20 53 74 72 69 6e 67 29 0d 0a 43 6f 6e 73 74 20}  //weight: 1, accuracy: High
        $x_1_2 = {29 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 0d 0a 20 20 20 49 66 20}  //weight: 1, accuracy: High
        $x_1_3 = "= 1 To Len(" ascii //weight: 1
        $x_1_4 = {20 3d 20 43 68 72 28 41 73 63 28 [0-15] 29 20 2b 20 33 29 0d 0a 20 20 20 49 66 20}  //weight: 1, accuracy: Low
        $x_1_5 = {20 3d 20 4d 69 64 28 [0-15] 2c 20 [0-15] 2c 20 31 29 0d 0a 20 20 20 49 66 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_F_2147729637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.F"
        threat_id = "2147729637"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell HdvqECIiNDCMPj + fDlqSGMbdISBN + LizQzKTL + ZSqmcFCHIwkJ, vbHide" ascii //weight: 1
        $x_1_2 = " & StrReverse(StrReverse(\"" ascii //weight: 1
        $x_1_3 = {76 73 75 77 75 6f 63 7a 6b 2e 52 75 6e 20 44 79 6a 6b 6d 77 74 7a 61 2e 55 65 61 64 6d 2c 20 30 2c 20 54 72 75 65 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_4 = {53 75 62 20 66 72 65 65 44 6f 63 75 6d 65 6e 74 32 28 69 29 0d 0a 57 69 74 68 20 55 73 65 72 46 6f 72 6d 31 0d 0a 49 66 20 69 20 3d 20 34 31 30 20 54 68 65 6e 20 53 68 65 6c 6c 20 2e 4c 61 73 74 54 65 78 74 2c 20 30 20 2a 20 69 0d 0a 45 6e 64 20 57 69 74 68 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_O97M_Obfuse_G_2147729677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.G"
        threat_id = "2147729677"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 [0-21] 2e 53 61 76 65 54 6f 46 69 6c 65 28 45 6e 76 69 72 6f 6e 28 [0-255] 29 2c 20 35 20 2b 20 33 20 2d 20 36 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 53 70 61 63 65 28 [0-4] 29 20 2b 20 55 43 61 73 65 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_H_2147729735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.H"
        threat_id = "2147729735"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 43 6f 6e 74 72 6f 6c 20 3d 20 22 54 65 78 74 42 6f 78 ?? 2c 20 30 2c 20 ?? 2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-6] 20 3d 20 [0-6] 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 64 61 74 61 54 79 70 65 20 3d 20 [0-6] 0d 0a 20 20 [0-6] 2e 54 65 78 74 20 3d 20 [0-6] 0d 0a 20 20 [0-6] 20 3d 20 53 74 72 43 6f 6e 76 28 [0-6] 2e 6e 6f 64 65 54 79 70 65 64 56 61 6c 75 65 2c 20 76 62 55 6e 69 63 6f 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_H_2147729735_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.H"
        threat_id = "2147729735"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 43 6f 6e 74 72 6f 6c 20 3d 20 22 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2c 20 ?? 2c 20 ?? 2c 20 4d 53 46 6f 72 6d 73 2c 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 22}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-6] 20 3d 20 [0-6] 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 [0-6] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 64 61 74 61 54 79 70 65 20 3d 20 [0-6] 0d 0a 20 20 [0-6] 2e 54 65 78 74 20 3d 20 [0-6] 0d 0a 20 20 [0-6] 20 3d 20 53 74 72 43 6f 6e 76 28 [0-6] 2e 6e 6f 64 65 54 79 70 65 64 56 61 6c 75 65 2c 20 76 62 55 6e 69 63 6f 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_I_2147729786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.I"
        threat_id = "2147729786"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 4c 65 6e 28 [0-32] 29 0d 0a 49 66 20 [0-32] 20 3c 3d 20 [0-32] 20 54 68 65 6e 0d 0a [0-32] 20 3d 20 [0-32] 20 2b 20 [0-32] 28 [0-32] 28 52 69 67 68 74 28 4c 65 66 74 28 [0-32] 2c 20 [0-32] 29 2c 20 31 29 29 2c 20 34 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 52 69 67 68 74 28 4c 65 66 74 28 [0-32] 2c 20 4c 65 6e 28 [0-32] 29 20 2b 20 [0-32] 20 2d 20 [0-32] 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_3 = {20 3c 3e 20 52 69 67 68 74 28 4c 65 66 74 28 [0-21] 2c 20 [0-21] 29 2c 20 31 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_J_2147729789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.J"
        threat_id = "2147729789"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = Len(" ascii //weight: 1
        $x_1_2 = {2c 20 4c 65 6e 28 [0-32] 29 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_3 = {20 3c 20 4c 65 6e 28 [0-32] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_10_4 = {2c 20 42 79 52 65 66 20 [0-21] 29 0d 0a [0-21] 20 3d 20 52 69 67 68 74 28 4c 65 66 74 28 [0-21] 2c 20 [0-21] 29 2c 20 31 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 10, accuracy: Low
        $x_1_5 = {53 75 62 20 [0-32] 28 42 79 52 65 66 20 [0-32] 2c 20 42 79 52 65 66 20}  //weight: 1, accuracy: Low
        $x_1_6 = {0d 0a 53 68 65 6c 6c 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_AS_2147729857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.AS"
        threat_id = "2147729857"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsError CVErr(" ascii //weight: 1
        $x_1_2 = {22 63 6d 64 2e 65 78 65 20 2f 63 20 50 5e 22 20 2b 20 90 02 10 43 68 72 90 05 01 01 57 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_K_2147729872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.K"
        threat_id = "2147729872"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "On Error Resume Next" ascii //weight: 1
        $x_1_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-32] 2c 20 54 72 75 65 2c 20 54 72 75 65 29 0d 0a [0-32] 2e 57 72 69 74 65 20 [0-32] 0d 0a [0-32] 2e 43 6c 6f 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = "With CreateObject(Chr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_AU_2147729988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.AU"
        threat_id = "2147729988"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsError CVErr(" ascii //weight: 1
        $x_1_2 = "\"md.exe /\" + Format(ChrW(" ascii //weight: 1
        $x_1_3 = "^e^l^L^.^E^X^e^" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_AV_2147730051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.AV"
        threat_id = "2147730051"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsError CVErr(" ascii //weight: 1
        $x_1_2 = {22 4d 64 2e 90 02 06 22 20 2b 20 46 6f 72 6d 61 74 28 43 68 72 57 28}  //weight: 1, accuracy: High
        $x_1_3 = "^b^g^B^0^A^C^k^A^L^g^B^E^A^G^8^A^d^w^B^u^A^G^w^" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_L_2147730072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.L"
        threat_id = "2147730072"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = Len(" ascii //weight: 1
        $x_1_2 = {2c 20 4c 65 6e 28 [0-32] 29 20 2b 20}  //weight: 1, accuracy: Low
        $x_10_3 = {2c 20 42 79 52 65 66 20 [0-21] 29 0d 0a [0-21] 20 3d 20 52 69 67 68 74 28 4c 65 66 74 28 [0-21] 2c 20 [0-21] 29 2c 20 31 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 10, accuracy: Low
        $x_1_4 = {53 75 62 20 [0-32] 28 42 79 52 65 66 20 [0-32] 2c 20 42 79 52 65 66 20}  //weight: 1, accuracy: Low
        $x_1_5 = {0d 0a 53 68 65 6c 6c 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_AX_2147730111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.AX"
        threat_id = "2147730111"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub kxnWvm()" ascii //weight: 1
        $x_1_2 = "Call Shell(" ascii //weight: 1
        $x_1_3 = "omran = \"cmd.exe /V:ON/C\"\"set lW=o.crm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_AY_2147730155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.AY"
        threat_id = "2147730155"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Call Shell(" ascii //weight: 1
        $x_1_3 = {3d 20 22 63 6d 64 20 2f 56 3a 4f 4e 2f 43 22 22 73 65 74 [0-5] 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BA_2147730249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BA"
        threat_id = "2147730249"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dim wDTiIL(2)" ascii //weight: 1
        $x_1_2 = "wDTiIL(0) = InStrRev(jljNwd + ijsBIVMkvJqdUDjjwZjL " ascii //weight: 1
        $x_1_3 = "Dim BpjJZc(3)" ascii //weight: 1
        $x_1_4 = "Dim TlwlFf(3)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BB_2147730251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BB"
        threat_id = "2147730251"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub Document_open()" ascii //weight: 1
        $x_1_2 = {0d 0a 43 6f 6e 73 74 20 0f 00 20 3d 20 0f 00 20 2d 20 0f 00 0d 0a 53 68 65 6c 6c 40 20 53 68 61 70 65 73 28 31 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 20 2b 20 0f 00 20 2b 20 0f 00 2c 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BC_2147730265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BC"
        threat_id = "2147730265"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub Document_open()" ascii //weight: 1
        $x_1_2 = {0d 0a 43 6f 6e 73 74 20 [0-32] 20 3d 20 [0-15] 20 2d 20 [0-32] 53 68 65 6c 6c 40 20 53 68 61 70 65 73 28 [0-112] 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 20 2b 20 0f 00 20 2b 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BD_2147730270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BD"
        threat_id = "2147730270"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4d 64 2e 22 20 2b [0-48] 2b 20 46 6f 72 6d 61 74 28 43 68 72 [0-1] 28}  //weight: 2, accuracy: Low
        $x_2_2 = {22 4d 64 22 20 2b 20 43 68 72 28 53 71 72 28 [0-32] 29 29 20 2b 20 22 22 20 2b 20 46 6f 72 6d 61 74 28 43 68 72}  //weight: 2, accuracy: Low
        $x_2_3 = {22 64 2e 22 20 2b 20 46 6f 72 6d 61 74 28 43 68 72 28 28 28 [0-32] 29 29 29 20 2b 20 22 [0-1] 22 20 2b 20 46 6f 72 6d 61 74 28 43 68 72 28 28 28}  //weight: 2, accuracy: Low
        $x_1_4 = "b#g#B#0#A#C#k#A#L#g#B#E#A#G#8#A#d#w#B#u#A#G#w#A#b#w#B#h#A#G#Q#A#R#g#B#p#A#G#w#A#Z#Q#A#o#A#C#I" ascii //weight: 1
        $x_1_5 = "%b%g%B%0%A%C%k%A%L%g%B%E%A%G%8%A%d%w%B%u%A%G%w%A%b%w%B%h%A%G%Q%A%R%g%B%p%A%G%w%A%Z%Q%A%o%A%C%I" ascii //weight: 1
        $x_1_6 = "@b@g@B@0@A@C@k@A@L@g@B@E@A@G@8@A@d@w@B@u@A@G@w@A@b@w@B@h@A@G@Q@A@R@g@B@p@A@G@w@A@Z@Q@A@o@A@C@I" ascii //weight: 1
        $x_1_7 = "_A_G_8_A_d_w_B_u_A_G_w_A_b_w_B_h_A_G_Q_A_R_g_B_p_A_G_w_A_Z_Q_A_o_A_C_I_A_a_A_B_0_A_H_Q_A_" ascii //weight: 1
        $x_1_8 = "!A!G!8!A!d!w!B!u!A!G!w!A!b!w!B!h!A!G!Q!A!R!g!B!p!A!G!w!A!Z!Q!A!o!A!C!I!A!a!A!B!0!A!H!Q!A!" ascii //weight: 1
        $x_1_9 = "^A^G^8^A^d^w^B^u^A^G^w^A^b^w^B^h^A^G^Q^A^R^g^B^p^A^G^w^A^Z^Q^A^o^A^C^I^A^a^A^B^0^A^H^Q^A^" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Obfuse_BE_2147730271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BE"
        threat_id = "2147730271"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 0a 53 68 65 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_3 = " (KeyString(" ascii //weight: 1
        $x_1_4 = " + KeyString(" ascii //weight: 1
        $x_1_5 = "(0) = " ascii //weight: 1
        $x_1_6 = "(1) = " ascii //weight: 1
        $x_1_7 = {44 69 6d 20 [0-15] 28 32 29 0d 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_O97M_Obfuse_BF_2147730287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BF"
        threat_id = "2147730287"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub Document_open()" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 40 20 53 68 61 70 65 73 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 28 22 22 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 53 68 61 70 65 73 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {56 42 41 2e 53 68 65 6c 6c 28 53 68 61 70 65 73 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-2] 20 2b 20 [0-32] 20 2b 20 [0-32] 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {53 68 65 6c 6c 28 53 68 61 70 65 73 28 [0-2] 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 20 2b 20 [0-32] 20 2b 20 [0-32] 2c 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_O97M_Obfuse_BG_2147730310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BG"
        threat_id = "2147730310"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cG93ZXJzaGVsbC5leGUgLUV4ZWN1dGlvblBvbGljeSBCeXBhc3" ascii //weight: 1
        $x_1_2 = "LVdpbmRvd1N0eWxlIGhpZGRlbiAtbm9sb2dvIC1ub3Byb2ZpbGUgLW" ascii //weight: 1
        $x_1_3 = "SUVYKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRGaWxlK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_O97M_Obfuse_BG_2147730310_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BG"
        threat_id = "2147730310"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub Document_open()" ascii //weight: 1
        $x_1_2 = {53 68 61 70 65 73 28 22 [0-32] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 61 70 65 73 28 [0-32] 20 2b 20 22 [0-32] 22 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_4 = {49 6e 74 65 72 61 63 74 69 6f 6e [0-5] 2e 53 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {46 69 78 28 [0-32] 20 2b 20 48 65 78 28 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_6 = {53 68 61 70 65 73 28 [0-32] 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 6f 6e 74 61 69 6e 69 6e 67 52 61 6e 67 65}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 53 68 61 70 65 73 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-2] 20 2b 20 [0-32] 20 2b 20 [0-32] 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 6f 6e 74 61 69 6e 69 6e 67 52 61 6e 67 65}  //weight: 1, accuracy: Low
        $x_1_8 = {53 68 65 6c 6c 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_O97M_Obfuse_BH_2147730311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BH"
        threat_id = "2147730311"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "Sub AutoClose()" ascii //weight: 1
        $x_1_3 = {53 68 61 70 65 73 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-2] 20 2b 20 [0-32] 20 2b 20 [0-32] 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 6f 6e 74 61 69 6e 69 6e 67 52 61 6e 67 65}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 61 70 65 73 28 [0-32] 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 6f 6e 74 61 69 6e 69 6e 67 52 61 6e 67 65}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 53 68 65 6c 6c [0-1] 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_6 = {53 68 65 6c 6c 10 00 20 10 00 20 2b 20 10 00 20 2b 20 10 00 2c 10 00}  //weight: 1, accuracy: Low
        $x_2_7 = {53 68 65 6c 6c [0-1] 20 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 [0-16] 20 2d 20 [0-16] 20 2a 20}  //weight: 2, accuracy: Low
        $x_1_8 = "Interaction.Shell" ascii //weight: 1
        $x_1_9 = "VBA.Shell" ascii //weight: 1
        $x_1_10 = {2e 52 75 6e 40 20 [0-32] 2c 20}  //weight: 1, accuracy: Low
        $x_2_11 = {2e 52 75 6e 20 54 72 69 6d 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_12 = {20 43 61 6c 6c 20 53 68 65 6c 6c [0-1] 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_13 = {28 53 68 65 6c 6c 28 54 72 69 6d 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_14 = {28 53 68 65 6c 6c 28 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_15 = {53 68 65 6c 6c ?? 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_16 = {53 68 65 6c 6c ?? 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_17 = {53 68 65 6c 6c [0-3] 52 54 72 69 6d 28 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 29 [0-1] 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_1_18 = {49 6e 74 65 72 61 63 74 69 6f 6e ?? 2e 53 68 65 6c 6c 28 43 6c 65 61 6e 53 74 72 69 6e 67 28 [0-32] 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 1, accuracy: Low
        $x_2_19 = {49 6e 74 65 72 61 63 74 69 6f 6e ?? 2e 53 68 65 6c 6c 20 01 00 54 72 69 6d 28 01 00 54 72 69 6d 28 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 29 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_2_20 = {41 72 72 61 79 28 [0-3] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e ?? 2e 53 68 65 6c 6c 28 4c 54 72 69 6d 28 52 54 72 69 6d 28 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 29 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 2, accuracy: Low
        $x_1_21 = {41 72 72 61 79 28 [0-16] 2c 20 [0-16] 2c 20 49 73 45 72 72 6f 72 28 [0-16] 29 2c 20 49 73 45 72 72 6f 72 28 53 68 65 6c 6c 28 43 6c 65 61 6e 53 74 72 69 6e 67 28 [0-16] 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_22 = {49 73 41 72 72 61 79 28 41 72 72 61 79 28 [0-16] 2c 20 [0-16] 2c 20 49 73 4e 75 6d 65 72 69 63 28 [0-16] 29 2c 20 49 73 45 72 72 6f 72 28 53 68 65 6c 6c 28 43 6c 65 61 6e 53 74 72 69 6e 67 28 [0-16] 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_23 = {49 73 45 72 72 6f 72 28 53 68 65 6c 6c 28 43 6c 65 61 6e 53 74 72 69 6e 67 28 [0-16] 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_24 = {49 73 4f 62 6a 65 63 74 28 53 68 65 6c 6c 28 4c 54 72 69 6d 28 [0-16] 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_25 = {49 73 45 72 72 6f 72 28 [0-32] 29 2c 20 49 73 4f 62 6a 65 63 74 28 53 68 65 6c 6c 28 54 72 69 6d 28 [0-32] 29 2c 20 [0-16] 20 2a 20 [0-16] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_26 = {53 68 65 6c 6c 28 [0-80] 2b 20 54 72 69 6d 28 [0-32] 29 20 2b 20 [0-96] 2c 20 [0-16] 20 2a 20 [0-6] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_27 = {53 68 65 6c 6c ?? 28 [0-152] 2c 20 [0-16] 20 2a 20 [0-6] 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_28 = {56 42 41 2e 53 68 65 6c 6c ?? 20 22 43 6d 44 20 2f 43 20 22 20 2b 20 54 72 69 6d 28 [0-32] 29 20 2b 20 [0-32] 20 2b 20 54 72 69 6d 28 52 65 70 6c 61 63 65 28 [0-32] 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 20 2b 20 22 22 2c 20 22 5b 22 2c 20 22 41 22 29 29 20 2b 20 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 2c 20 43 49 6e 74 28 [0-16] 20 2a 20 [0-6] 20 2b 20}  //weight: 1, accuracy: Low
        $x_2_29 = {53 68 65 6c 6c ?? 20 53 68 61 70 65 73 28 54 72 69 6d 28 22 [0-32] 22 29 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 76 62 48 69 64 65}  //weight: 2, accuracy: Low
        $x_2_30 = {53 68 65 6c 6c 20 53 68 61 70 65 73 28 22 [0-32] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 76 62 48 69 64 65}  //weight: 2, accuracy: Low
        $x_2_31 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c ?? 20 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 31 20 2b 20 31 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 76 62 48 69 64 65}  //weight: 2, accuracy: Low
        $x_2_32 = {53 68 65 6c 6c ?? 20 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 32 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 76 62 48 69 64 65}  //weight: 2, accuracy: Low
        $x_2_33 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c ?? 20 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 31 20 2b 20 [0-32] 20 2d 20 31 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c}  //weight: 2, accuracy: Low
        $x_2_34 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c ?? 20 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-16] 20 2f 20 [0-16] 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 30}  //weight: 2, accuracy: Low
        $x_2_35 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c ?? 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-16] 20 2f 20 [0-16] 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Obfuse_BI_2147730312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BI"
        threat_id = "2147730312"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 0a 53 68 65 6c 6c 20}  //weight: 10, accuracy: High
        $x_1_2 = " = Environ(\"Te\" & \"\" & \"mp\")" ascii //weight: 1
        $x_1_3 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 20 26 20 22 73 63 72 69 70 74 69 6e 67 22 20 26 20 22 2e 66 69 6c 65 73 79 73 74 22 20 26 20 22 65 6d 6f 62 6a 65 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-32] 20 26 20 22 73 79 73 74 65 6d 72 6f 6f 74 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Obfuse_R_2147730378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.R"
        threat_id = "2147730378"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Shapes(1).TextFrame.TextRange.Text" ascii //weight: 1
        $x_1_2 = "Private Sub Document_open()" ascii //weight: 1
        $x_1_3 = {53 68 65 6c 6c 28 [0-32] 20 2b 20 [0-32] 20 2b 20 [0-32] 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BJ_2147730476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BJ"
        threat_id = "2147730476"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"bQBzAGkAZQB4AGUAYwAuAGUAeABlACAALwBp" ascii //weight: 1
        $x_1_2 = "Call Shell(" ascii //weight: 1
        $x_1_3 = "= \"MICrOSOFT.XMLdOM\"" ascii //weight: 1
        $x_1_4 = ") & Chr$(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BK_2147730517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BK"
        threat_id = "2147730517"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-64] 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 [0-64] 2c 20 31 29 29 20 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-32] 29 20 53 74 65 70 20 32 0d 0a [0-64] 20 26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-48] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 [0-64] 3d 20 2e 43 6f 75 6e 74 20 54 6f 20 31 20 53 74 65 70 20 2d 31 [0-21] 2e 49 74 65 6d 28 [0-32] 29 2e 44 65 6c 65 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BL_2147730518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BL"
        threat_id = "2147730518"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-64] 29 29 0d 0a 20 20 20 20 45 6c 73 65 0d 0a 20 20 20 20 20 20 20 20 53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-64] 29 29 0d 0a 20 20 20 20 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_2 = {20 43 68 72 28 41 73 63 28 4d 69 64 28 [0-64] 2c 20 31 29 29 20 2d}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 52 75 6e 20 [0-32] 2c 20 [0-32] 2c 20 54 72 75 65 0d 0a 20 20 20 20 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 29 0d 0a 20 20 20 20 53 65 6c 65 63 74 69 6f 6e 2e 57 68 6f 6c 65 53 74 6f 72 79 0d 0a 20 20 20 20 53 65 6c 65 63 74 69 6f 6e 2e 46 6f 6e 74 2e 43 6f 6c 6f 72 20 3d 20 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 0a 20 20 20 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 28 30 2c 20 30 29 2e 53 65 6c 65 63 74 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 [0-64] 3d 20 2e 43 6f 75 6e 74 20 54 6f 20 31 20 53 74 65 70 20 2d 31 [0-21] 2e 49 74 65 6d 28 [0-32] 29 2e 44 65 6c 65 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BM_2147730589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BM"
        threat_id = "2147730589"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Attribute VB_Name = \"kaipwUzwB\"" ascii //weight: 1
        $x_1_2 = "VB_Name = \"bwiOniizVBh\"" ascii //weight: 1
        $x_1_3 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_4 = {3d 20 22 22 20 2b 20 08 00 20 2b 20 08 00 20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 20 2b 20 08 00 20 2b 20 09 00}  //weight: 1, accuracy: Low
        $x_1_5 = {49 66 20 44 69 72 28 08 00 29 20 3d 20 22 22 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_O97M_Obfuse_BN_2147730591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BN"
        threat_id = "2147730591"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 4c 65 72 63 65 6e 74 5f 43 68 61 6e 67 65 28 29 0d 0a 44 69 6d 20 69 6e 64 31 20 41 73 20 53 74 72 69 6e 67 0d 0a 69 6e 64 31 20 3d 20 22 31 30 30 36 22 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_2 = ".Text1, Len(" ascii //weight: 1
        $x_1_3 = {20 3d 20 4c 65 6e 28 [0-32] 2e 4c 61 73 74 54 65 78 74 29}  //weight: 1, accuracy: Low
        $x_1_4 = {20 54 68 65 6e 20 53 68 65 6c 6c 20 2e 4c 61 73 74 54 65 78 74 2c 20 [0-15] 0d 0a 45 6e 64 20 57 69 74 68 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BO_2147730627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BO"
        threat_id = "2147730627"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_5_2 = {3d 20 53 68 61 70 65 73 28 [0-32] 29}  //weight: 5, accuracy: Low
        $x_2_3 = "VBA.Shell% " ascii //weight: 2
        $x_2_4 = "Interaction.Shell(" ascii //weight: 2
        $x_1_5 = ".TextFrame.TextRange.Text + " ascii //weight: 1
        $x_2_6 = ".TextFrame.ContainingRange" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Obfuse_BP_2147730629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BP"
        threat_id = "2147730629"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = " = Environ(\"Temp\")" ascii //weight: 1
        $x_1_3 = " = CreateObject(\"scripting.filesystemobject\")" ascii //weight: 1
        $x_1_4 = " = Environ(\"SystemRoot\")" ascii //weight: 1
        $x_1_5 = {0d 0a 53 68 65 6c 6c 20}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 6c 65 63 74 20 43 61 73 65 20 [0-32] 0d 0a 43 61 73 65 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BQ_2147730684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BQ"
        threat_id = "2147730684"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= StrReverse(\"QeTxXeF." ascii //weight: 1
        $x_1_2 = "Shell (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BR_2147730756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BR"
        threat_id = "2147730756"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "Sub AutoClose()" ascii //weight: 1
        $x_1_3 = "Shapes(" ascii //weight: 1
        $x_1_4 = "Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_O97M_Obfuse_BX_2147730772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BX"
        threat_id = "2147730772"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 61 70 65 73 28 22 10 00 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 20 2b [0-16] 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 52 75 6e [0-21] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38 22 20 2b 20 [0-48] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BS_2147730785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BS"
        threat_id = "2147730785"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 45 64 69 74 54 65 78 74 31 5f 43 68 61 6e 67 65 28 29 0d 0a 44 69 6d 20 69 6e 64 31 20 41 73 20 53 74 72 69 6e 67 0d 0a 69 6e 64 31 20 3d 20 22 31 30 30 37 22 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_2 = ".Text1, Len(" ascii //weight: 1
        $x_1_3 = {20 3d 20 4c 65 6e 28 [0-32] 2e 4c 61 73 74 54 65 78 74 29}  //weight: 1, accuracy: Low
        $x_1_4 = {20 54 68 65 6e 20 53 68 65 6c 6c 20 [0-32] 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BT_2147730805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BT"
        threat_id = "2147730805"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 45 64 69 74 54 65 78 74 31 5f 43 68 61 6e 67 65 28 29 0d 0a 44 69 6d 20 69 6e 64 31 20 41 73 20 53 74 72 69 6e 67 0d 0a 69 6e 64 31 20 3d 20 22 31 30 30 01 00 22}  //weight: 1, accuracy: Low
        $x_1_2 = ".Text1, Len(" ascii //weight: 1
        $x_1_3 = "= .LastText" ascii //weight: 1
        $x_1_4 = {20 54 68 65 6e 20 53 68 65 6c 6c 20 [0-32] 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_D_2147730810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.D"
        threat_id = "2147730810"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = {20 3d 20 48 65 78 28 ?? ?? ?? ?? ?? ?? 29}  //weight: 1, accuracy: Low
        $x_1_3 = {20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38 22 20 2b 20 [0-9] 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".TextFrame.TextRange.Text +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BU_2147730852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BU"
        threat_id = "2147730852"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 68 61 70 65 73 28 22 10 00 22 29}  //weight: 10, accuracy: Low
        $x_10_2 = ".TextFrame.TextRange.Text + " ascii //weight: 10
        $x_1_3 = {2e 52 75 6e 20 [0-16] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 52 75 6e 21 [0-16] 2c}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 52 75 6e 23 [0-16] 2c}  //weight: 1, accuracy: Low
        $x_10_6 = "\"new:72C24DD5-D70A-438B-8A42-98424B88AFB8\" + " ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Obfuse_RU_2147730962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.RU"
        threat_id = "2147730962"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub Document_open()" ascii //weight: 1
        $x_1_2 = {5b 49 6e 74 65 72 61 63 74 69 6f 6e 5d 2e 53 68 65 6c 6c 28 [0-16] 2c 20 [0-16] 29 2c 20 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".TextRange.Text" ascii //weight: 1
        $x_1_4 = {53 68 61 70 65 73 28 22 [0-32] 22 29 2e 54 65 78 74 46 72 61 6d 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BV_2147731002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BV"
        threat_id = "2147731002"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "red_fix sb1, arg1, per2" ascii //weight: 1
        $x_1_2 = "doc_print_body Form1.Text1" ascii //weight: 1
        $x_1_3 = {53 68 65 6c 6c 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BZ_2147731036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BZ"
        threat_id = "2147731036"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 61 70 65 73 28 [0-32] 20 2b 20 22 [0-32] 22 20 2b 20 [0-32] 29 2e 54 65 78 74 46 72 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_2 = {49 6e 74 65 72 61 63 74 69 6f 6e [0-15] 53 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "ContainingRange" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CA_2147731151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CA"
        threat_id = "2147731151"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Shell(" ascii //weight: 1
        $x_1_2 = {20 3d 20 41 72 72 61 79 28 [0-16] 2c 20 [0-16] 2c 20 [0-16] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 20 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 53 68 61 70 65 73 28 [0-16] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CA_2147731151_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CA"
        threat_id = "2147731151"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 53 68 61 70 65 73 28 90 1d 15 00 20 2b 20 22 90 1d 15 00 22 20 2b 20 90 1d 15 00 29 90}  //weight: 1, accuracy: High
        $x_1_2 = {41 72 72 61 79 28 90 02 30 49 6e 74 65 72 61 63 74 69 6f 6e 90 05 30 0a 2e 21 40 23 20 5d 5b 5f 0d 0a 53 68 65 6c 6c 28 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CB_2147731170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CB"
        threat_id = "2147731170"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Shell(" ascii //weight: 1
        $x_1_2 = {20 3d 20 41 72 72 61 79 28 [0-16] 2c 20 [0-16] 2c 20 [0-16] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 54 65 78 74 42 6f 78 31 20 2b 20 [0-10] 20 2b 20 [0-10] 20 2b 20 [0-10] 20 2b 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CC_2147731189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CC"
        threat_id = "2147731189"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"Sys\" &" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"scripting.filesystemobject\")" ascii //weight: 1
        $x_1_3 = "(Application.MailSystem) Like" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CG_2147731228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CG"
        threat_id = "2147731228"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Shell(" ascii //weight: 1
        $x_1_2 = {20 3d 20 41 72 72 61 79 28 [0-16] 2c 20 [0-16] 2c 20 [0-16] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 20 2b 20 [0-10] 20 2b 20 [0-10] 20 2b 20 [0-10] 20 2b 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CH_2147731266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CH"
        threat_id = "2147731266"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 72 72 61 79 28 [0-16] 2c 20 [0-16] 2c 20 [0-16] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 [0-80] 2e 54 65 78 74 42 6f 78 31 [0-64] 2c 20 03 00 20 2d 20 03 00 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CD_2147731322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CD"
        threat_id = "2147731322"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 70 6f 77 22 20 2b 20 10 00 20 2b 20 10 00 20 2b 20 22 65 72 22 20 2b 20 10 00 20 2b 20 10 00 20 2b 20 22 73 68 22 20 2b 20 10 00 20 2b 20 10 00 20 2b 20 22 65 22 20 2b 20 10 00 20 2b 20 10 00 20 2b 20 22 6c 22 20 2b 20 10 00 20 2b 20 10 00 20 2b 20 22 6c 20 20 22}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 28 10 00 2c 20 10 00 20 2d 20 10 00 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CE_2147731333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CE"
        threat_id = "2147731333"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 34 34 32 32 34 34 37 34 20 2f 20 10 00 20 2d 20 35 33 36 30 38 33 37 38 36 20 2b 20 43 53 6e 67 28 10 00 29 20 2b 20 32 20 2d 20 43 68 72 28 37 30 31 33 29 20 2d 20 10 00 20 2f 20 38 35 32 37 20 2a 20 10 00 20 2b 20 46 69 78 28 37 37 39 38 29 20 2b 20 39 39 30 35 20 2a 20 53 69 6e 28 37 29 20 2f 20 33 31 30 20 2a 20 53 69 6e 28 10 00 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 38 37 31 20 2f 20 52 6e 64 28 34 29 20 2b 20 10 00 20 2b 20 10 00 20 2a 20 39 20 2b 20 49 6e 74 28 10 00 20 2a 20 43 53 74 72 28 10 00 29 29 20 2b 20 10 00 20 2a 20 43 44 61 74 65 28 33 36 32 34 20 2d 20 33 35 32 31 38 33 34 36 37 20 2a 20 38 34 20 2f 20 34 37 35 29 20 2f 20 10 00 20 2d 20 43 53 6e 67 28 36 32 30 29}  //weight: 1, accuracy: Low
        $x_1_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 10 00 22 2c 20 10 00}  //weight: 1, accuracy: Low
        $x_1_4 = "= Mid(\"Y/,http:/'+'/'+'arteandvte+vteivte+vteni'+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_O97M_Obfuse_CF_2147731407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CF"
        threat_id = "2147731407"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"ob\" + ORzWcjqzFIkYid + mboGOHOwULN + \"jEC\" + vwmdjQDIIBfJ + akJOwZkC + \"T\" + pfGCwCRW + KJwvuNYW + \"  \" + JwJzoOKwQzA + bnDJAKGkJpsAQm + \"SY\" + jBOYYBsWJO + UFVMQKWHqDXMX + \"sT\" + GRwXbwc + lUaZvhAmaOPDUf + \"Em.\"" ascii //weight: 1
        $x_1_2 = "Shell(pHupaqZlUirzT, 159695327 - 159695327)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CJ_2147731685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CJ"
        threat_id = "2147731685"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 72 72 61 79 28 [0-32] 2c 20 [0-32] 2c 20 [0-32] 2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-112] 29 2e 52 75 6e [0-1] 28 28 [0-112] 2e 54 65 78 74 42 6f 78 31 [0-80] 2c 20 02 00 20 2d 20 02 00 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CK_2147731730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CK"
        threat_id = "2147731730"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 72 72 61 79 28 [0-25] 2c 20 [0-15] 2c 20 [0-10] 2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 52 69 70 74 2e 73 48 65 4c 6c 22 29 2e 52 75 6e [0-1] 28 28 22 22 20 2b 20 [0-90] 2e 54 65 78 74 42 6f 78 31 [0-70] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CL_2147731767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CL"
        threat_id = "2147731767"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-16] 22 2c 20}  //weight: 1, accuracy: Low
        $x_1_2 = {20 2b 20 53 68 65 6c 6c 28 [0-16] 20 2b 20 [0-16] 20 2b 20 [0-16] 2c 20 [0-16] 20 2d 20 [0-16] 29 20 2b 20}  //weight: 1, accuracy: Low
        $x_1_3 = "owe\" + \"rs\"" ascii //weight: 1
        $x_1_4 = "\"hell\" + \"  \" " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CM_2147731788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CM"
        threat_id = "2147731788"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 72 72 61 79 28 [0-32] 2c 20 [0-32] 2c 20 [0-32] 2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-153] 29 2e 52 75 6e [0-1] 28}  //weight: 1, accuracy: Low
        $x_1_2 = "\"WscRipt.sHeLl\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CN_2147731806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CN"
        threat_id = "2147731806"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 72 72 61 79 28 [0-64] 2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 20 2b 20 [0-144] 29 2e 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "\"WscRipt.sHeLl\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CO_2147731846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CO"
        threat_id = "2147731846"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_1_2 = "Sub autoopen22()" ascii //weight: 1
        $x_1_3 = {3d 20 41 72 72 61 79 28 [0-64] 2c 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a [0-64] 22 29 2e 52 75 6e 28 [0-64] 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 41 72 72 61 79 28 [0-64] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 [0-64] 29 2c 20}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 41 72 72 61 79 28 [0-64] 2c 20 53 68 65 6c 6c 28 [0-64] 29 2c 20}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 41 72 72 61 79 28 [0-64] 2c 20 [0-32] 28 53 68 65 6c 6c 28 [0-112] 2c 20 07 00 20 2d 20 07 00 29}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 43 68 6f 6f 73 65 28 [0-64] 2c 20 53 68 65 6c 6c 28 [0-112] 2c 20 07 00 20 2d 20 07 00 29}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 20 43 68 6f 6f 73 65 28 [0-64] 2c 20 43 6c 65 61 6e 53 74 72 69 6e 67 28 53 68 65 6c 6c 28 [0-112] 2c 20 07 00 20 2d 20 07 00 29}  //weight: 1, accuracy: Low
        $x_1_9 = {3d 20 43 6c 65 61 6e 53 74 72 69 6e 67 28 53 68 65 6c 6c 28 [0-112] 2c 20 07 00 20 2d 20 07 00 29}  //weight: 1, accuracy: Low
        $x_1_10 = {28 53 68 65 6c 6c 28 [0-32] 2c 20 76 62 48 69 64 65 29 29}  //weight: 1, accuracy: Low
        $x_1_11 = {28 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 [0-32] 2c 20 76 62 48 69 64 65 29 29}  //weight: 1, accuracy: Low
        $x_1_12 = {28 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 [0-32] 2c 20 [0-32] 29 2c 20 [0-32] 29}  //weight: 1, accuracy: Low
        $x_1_13 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 [0-32] 2c 20 [0-32] 29 2c}  //weight: 1, accuracy: Low
        $x_1_14 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 20 [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_O97M_Obfuse_CR_2147731900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CR"
        threat_id = "2147731900"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a [0-32] 20 3d 20 53 68 65 6c 6c 28 [0-32] 20 2b 20 [0-96] 2c 20 76 62 48 69 64 65 29 0d 0a 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CS_2147731923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CS"
        threat_id = "2147731923"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {3d 20 53 68 65 6c 6c 28 ?? ?? [0-32] 20 2b 20 ?? ?? [0-32] 20 2b 20 [0-96] 2c 20 76 62 48 69 64 65 29 0d 0a 0d 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_CT_2147733229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CT"
        threat_id = "2147733229"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Panda = \"dvfert36tge4tgf\"" ascii //weight: 1
        $x_1_2 = "Loading = \"dvfert36tge4tgf\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_O97M_Obfuse_CP_2147733739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.CP"
        threat_id = "2147733739"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "activedocument.shapes" ascii //weight: 1
        $x_1_2 = ".alternativetext" ascii //weight: 1
        $x_1_3 = {69 00 6e 00 74 00 65 00 72 00 61 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 76 00 62 00 68 00 69 00 64 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {69 6e 74 65 72 61 63 74 69 6f 6e 2e 73 68 65 6c 6c [0-80] 76 62 68 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_O97M_Obfuse_DH_2147733999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.DH"
        threat_id = "2147733999"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 6e 6d 22 20 2b 20 22 67 6d 74 22 20 2b 20 [0-16] 20 2b 20 22 73 3a 57 69 22 20 2b 20 22 6e 33 32 5f 50 72 22 20 2b 20 22 6f 63 65 73 73 53 74 22 20 2b 20 22 61 72 74 75 70 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_YA_2147734499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.YA!MTB"
        threat_id = "2147734499"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 55 73 65 72 46 6f 72 6d [0-2] 2e 54 65 78 74 42 6f 78 [0-2] 2e 54 65 78 74 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= CallByName(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_YA_2147734499_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.YA!MTB"
        threat_id = "2147734499"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 54 45 4d 50 25 5c [0-64] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 52 75 6e 20 [0-64] 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateObject(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_YB_2147740095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.YB!MTB"
        threat_id = "2147740095"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 22 [0-10] 2b [0-10] 2b [0-10] 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_YC_2147740112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.YC!MTB"
        threat_id = "2147740112"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 20 43 68 72 28 52 65 70 6c 61 63 65 28 22 [0-10] 22 2c 20 22 [0-10] 22 2c 20 [0-5] 29 20 2d 20 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateObject(\"WScript.Shell\").Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_YD_2147740567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.YD!MTB"
        threat_id = "2147740567"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 41 64 64 72 65 73 73 28 30 2c 20 30 29 22 3a 20 [0-16] 20 3d 20 53 68 65 6c 6c 28}  //weight: 1, accuracy: Low
        $x_1_2 = "ApplIcation.Quit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_RKA_2147744242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.RKA!eml"
        threat_id = "2147744242"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 4e 69 6c 57 69 6e 5c 4e 69 6c 57 69 6e 74 2e 62 61 74 22 2c 20 54 72 75 65 29 2e 00 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22}  //weight: 1, accuracy: Low
        $x_1_2 = ".CreateTextFile(Chr(99) & Chr(58) & Chr(92) & Chr(78) & Chr(105) & Chr(108) & Chr(87) & Chr(105) & Chr(110) & Chr(92) & Chr(78) & Chr(105) & Chr(108) & Chr(87) & Chr(105) & Chr(110) & Chr(116) & Chr(46) & Chr(118) & Chr(98) & Chr(115), True)" ascii //weight: 1
        $x_1_3 = "DeleteFile = \"c:\\NilWin\\NilWint.bat\"" ascii //weight: 1
        $x_1_4 = "c:\\NilWin\\NilWint.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_O97M_Obfuse_SR_2147751666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.SR!MTB"
        threat_id = "2147751666"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ExecCmd(cmdline As String)" ascii //weight: 1
        $x_1_2 = "= CreateProcessA(" ascii //weight: 1
        $x_1_3 = {45 78 65 63 43 6d 64 20 22 43 3a 5c [0-16] 5c [0-10] 2e 42 41 54 22}  //weight: 1, accuracy: Low
        $x_1_4 = {45 78 65 63 43 6d 64 20 22 43 3a 5c [0-10] 5c [0-10] 5c [0-10] 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_AAY_2147752040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.AAY!MTB"
        threat_id = "2147752040"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 55 6e 70 72 6f 74 65 63 74 20 22 [0-15] 23 45 44 43 22}  //weight: 1, accuracy: Low
        $x_1_2 = {20 2b 20 22 65 78 65 63 28 [0-10] 2e 75 72 6c 6f 70 65 6e 28 [0-10] 2e 52 65 71 75 65 73 74 28 27 68 74 74 70 3a 2f 2f 63 72 70 68 6f 6e 65 2e 6d 69 72 65 65 6e 65 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_3 = {70 6f 70 65 6e 28 22 70 79 74 68 6f 6e 20 2d 63 20 22 22 22 20 2b 20 [0-10] 20 2b 20 22 22 22 22 2c 20 22 72 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_AAYT_2147752044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.AAYT!MTB"
        threat_id = "2147752044"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 55 6e 70 72 6f 74 65 63 74 20 22 [0-31] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6d 64 20 3d 20 63 6d 64 20 2b 20 22 65 78 65 63 28 75 72 6c 6c 69 62 32 2e 75 72 6c 6f 70 65 6e 28 75 72 6c 6c 69 62 32 2e 52 65 71 75 65 73 74 28 27 68 74 74 70 3a 2f 2f [0-95] 2e 72 65 61 64 28 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {70 6f 70 65 6e 28 22 70 79 74 68 6f 6e 20 2d 63 20 22 22 22 20 2b 20 [0-10] 20 2b 20 22 22 22 22 2c 20 22 72 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_GA_2147757165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.GA!MSR"
        threat_id = "2147757165"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Microsoft_JhengHei = Simplified_Arabic(\"dnammoCdedocnE- neddiH wodniW- poN- atS- llehsrewop\")" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_JI_2147760965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.JI!MTB"
        threat_id = "2147760965"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileName = \"*.jpg ; *.jpe ; *.bmp ; *.gif ; *.avi ; *.wav ; *.mid ; *.mpg ; *.mp2 ; *.mp3 ; *.zip ; *.rar ; *.arj ; *.htm ; *.html" ascii //weight: 1
        $x_1_2 = "Kill fs.FoundFiles(j)" ascii //weight: 1
        $x_1_3 = "LookIn = \"C:\\ ; D:\\ ; E:\\ ; F:\\ ; G:\\ ; H:\\ ; I:\\ ; J:\\ ; K:\\ ; L:\\ ; M:\\ ; N:\\ ; O:\\ ; P:\\ ; Q:\\ ; R:\\ ; S:\\ ; T:\\ ; U:\\ ; V:\\ ; W:\\ ; X:\\ ; Y:\\ ; Z:\\" ascii //weight: 1
        $x_1_4 = "WordBasic.DisableAutoMacros -1" ascii //weight: 1
        $x_1_5 = "Selection.Font.Animation = wdAnimationBlinkingBackground" ascii //weight: 1
        $x_1_6 = "Kill (XLS.StartupPath + Chr(92) + Chr(66) + Chr(111) + Chr(111) + Chr(107) + Chr(49) + Chr(46))" ascii //weight: 1
        $x_1_7 = "regedit.RegWrite \"\"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools\"\", 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BAT_2147762181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BAT!MTB"
        threat_id = "2147762181"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function df9e122e(a600af58)" ascii //weight: 1
        $x_1_2 = "Set b8acfabf = CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_3 = "Call b8acfabf.exec(a600af58)" ascii //weight: 1
        $x_1_4 = "dcd3f665 = ActiveDocument.Shapes(1).Title + \" \" + f5d112a0" ascii //weight: 1
        $x_1_5 = "e5fbd99d = f5a419b7.c492b9b9(ActiveDocument.Shapes(ed71ee4c).AlternativeText)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_BAS_2147762670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.BAS!MTB"
        threat_id = "2147762670"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call f88ccd55.exec(d533a26d)" ascii //weight: 1
        $x_1_2 = "e689f7ea.Open \"GET\", f6cd39d8, False" ascii //weight: 1
        $x_1_3 = "b0377985 = Split(b9e2634d, \"|\")" ascii //weight: 1
        $x_1_4 = "ca71f859.da502b63 e516b94e(0) +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_PFF_2147763053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.PFF"
        threat_id = "2147763053"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b7be34d3 = StrConv(c30d2d87, vbUnicode)" ascii //weight: 1
        $x_1_2 = "ea0394e8 = Split(e9b5de74, \"|\")" ascii //weight: 1
        $x_1_3 = "a07a5752.fda05149 bd3e4c5e(0) + \" \" + da03d24f(\"pdf\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_JL_2147763220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.JL!MTB"
        threat_id = "2147763220"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Array(\"@chd.com.cn\", \"@cfitc.com\", \"@cg.com.cn\", \"@chder.com\", \"@chdhk.com\", \"@chdi.ac.cn\", \"@chdoc.com.cn" ascii //weight: 1
        $x_1_2 = "Load \"http://10.79.22.10:8080/?eref=\" & Email" ascii //weight: 1
        $x_1_3 = "&mref=\" & Environ(\"ComputerName\") & \"&uref=\" & Environ(\"Username\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_SC_2147766865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.SC!MTB"
        threat_id = "2147766865"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 22 25 63 6f 6d 73 70 65 63 25 2f 63 73 74 61 72 74 2f 77 61 69 74 63 3a 5c [0-21] 5c [0-21] 2e 76 62 73}  //weight: 2, accuracy: Low
        $x_1_2 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 22 72 65 67 73 76 72 33 32 2e 65 78 65 2d 73 63 3a 5c [0-21] 5c [0-21] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_SC_2147766865_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.SC!MTB"
        threat_id = "2147766865"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "createobject(\"wscript.shell\").exec\"%comspec%/cstart/waitc:\\gophotonics\\reddit.vbs" ascii //weight: 2
        $x_1_2 = "createobject(\"wscript.shell\").exec\"regsvr32.exe-sc:\\gophotonics\\waveplate.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_SE_2147767470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.SE!MTB"
        threat_id = "2147767470"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hournow=hour(time())ifhournow<30then" ascii //weight: 1
        $x_1_2 = "ifapplication.operatingsystemlike\"*windows*\"then" ascii //weight: 1
        $x_1_3 = "winhttp.winhttprequest.5.1" ascii //weight: 1
        $x_1_4 = {65 78 65 63 75 74 65 28 22 22 [0-15] 3d 6e 6f 76 61 72 75 65 2b 22 22 22 22 74 79 70 65 64 76 61 6c 75 65 22 22 22 22 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_SF_2147767475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.SF!MTB"
        threat_id = "2147767475"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setobj=createobject(\"excel.application\")" ascii //weight: 1
        $x_1_2 = "obj.ddeinitiate\"explorer.exe\",\"c:\\hddrput\\daogfdkgbad.vbe" ascii //weight: 1
        $x_1_3 = "open\"c:\\hddrput\\daogfdkgbad.vbe\"foroutputaccesswriteas#1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_LF_2147769351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.LF!MTB"
        threat_id = "2147769351"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If \"eyRRxYSoVOJbcmAFdwAoQNVDCoubHYauMgTkqEnOPoiVWxWYHtwHyBaQdNOIdrhwoPPwTP\" = \"YJmZbfzgESWTNbSvKGDHcpekXH\" Then" ascii //weight: 1
        $x_1_2 = {52 65 70 6c 61 63 65 28 [0-8] 2c 20 22 [0-36] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 52 75 6e 20 [0-10] 2c 20 2d 31}  //weight: 1, accuracy: Low
        $x_1_4 = "EA = 93" ascii //weight: 1
        $x_1_5 = "CLZe = 60" ascii //weight: 1
        $x_1_6 = "Int((6 * Rnd) + 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_AL_2147769618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.AL!MTB"
        threat_id = "2147769618"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(" ascii //weight: 1
        $x_1_2 = "+ Chr(CLng((wdTableFormatWeb2 Xor wdKeyF7))) +" ascii //weight: 1
        $x_1_3 = "= Join(Array(" ascii //weight: 1
        $x_1_4 = "(wdLayoutModeGrid Xor wdOMathHorizAlignLeft)" ascii //weight: 1
        $x_1_5 = "((wdTableFormatWeb2 Xor wdKeyF7))) + ChrW(CLng((Not (" ascii //weight: 1
        $x_1_6 = "Chr(CLng((wdBaselineAlignTop Or wdFieldFormDropDown))) + Chr(CLng((AscW(\"l\"))))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_SH_2147771880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.SH!MTB"
        threat_id = "2147771880"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "setobj=createobject(\"excel.application\")" ascii //weight: 1
        $x_1_2 = {6f 62 6a 2e 64 64 65 69 6e 69 74 69 61 74 65 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 22 2c 22 63 3a 5c [0-15] 5c [0-15] 2e 76 62 65}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 70 65 6e 22 63 3a 5c [0-15] 5c [0-15] 2e 76 62 65 22 66 6f 72 6f 75 74 70 75 74 61 63 63 65 73 73 77 72 69 74 65 61 73 23 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_RT_2147816042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.RT!MTB"
        threat_id = "2147816042"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=shellexecute(1,strreverse(\"nepo\"),strreverse(\"exe.llehsrewop\"),strreverse(\"exe.yttup\\pmet\\swodniw\\:cexe.rerolpxe;exe.yttup\\pmet\\swodniw\\:co-exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_RLP_2147847346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.RLP!MTB"
        threat_id = "2147847346"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.yttup/321/231.031.271.701//:ptth" ascii //weight: 1
        $x_1_2 = "strreverse(\"\\0.1v\\llehsrewopswodniw\\23metsys\\swodniw\\:c\"))endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_RP_2147849487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.RP!MTB"
        threat_id = "2147849487"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "^p*o^*w*e*r*s^^*h*e*l^*l**^-*w*i*n*^d*o*w^*s*t*y*^l*e**h*i*^d*d*^e*n^**-*e*x*^e*c*u*t*^i*o*n*pol^icy**b*yp^^ass*;*$tempfile**=**[*i*o*.*p*a*t*h*]*::gettem*pfile*name()|ren^ame-it^em-newname{$_-replace'tmp$','exe'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_RP_2147849487_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.RP!MTB"
        threat_id = "2147849487"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 50 22 3a 20 [0-7] 20 3d 20 22 6f 22 3a 20 [0-7] 20 3d 20 22 77 22 3a 20 [0-7] 20 3d 20 22 65 22 3a 20 [0-7] 20 3d 20 22 72 22 3a 20 [0-7] 20 3d 20 22 73 22 3a 20 [0-7] 20 3d 20 22 68 22 3a 20 [0-7] 20 3d 20 22 65 22 3a 20 [0-9] 20 3d 20 22 6c 22 3a 20 [0-9] 20 3d 20 22 6c 22 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 57 22 3a 20 [0-7] 20 3d 20 22 53 22 3a 20 [0-7] 20 3d 20 22 63 22 3a 20 [0-7] 20 3d 20 22 72 22 3a 20 [0-7] 20 3d 20 22 69 22 3a 20 [0-7] 20 3d 20 22 70 22 3a 20 [0-7] 20 3d 20 22 68 22 3a 20 [0-7] 20 3d 20 22 74 22 3a 20 [0-7] 20 3d 20 22 2e 22 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-9] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_RP_2147849487_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.RP!MTB"
        threat_id = "2147849487"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".open\"get\",(\"h://www.vmd.m/mw/hd.\"),false.send=.responsebodyif.status=200thenset=createobject(\"adodb.stream\").open.type=.write.savetofile,+.closeendif.open()end" ascii //weight: 1
        $x_1_2 = "set=createobject(\"microsoft.xmlhttp\")set=createobject(\"shell.application\")=" ascii //weight: 1
        $x_1_3 = {2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 72 65 63 65 6e 74 22 29 64 69 6d 64 69 6d 64 69 6d 64 69 6d 64 69 6d 64 69 6d 61 73 69 6e 74 65 67 65 72 64 69 6d 64 69 6d 3d 31 72 61 6e 67 65 28 22 [0-4] 22 29 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = "=chr(50)+chr(48)+chr(48)" ascii //weight: 1
        $x_1_5 = "=createobject(\"wscript.shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_RPI_2147888289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.RPI!MTB"
        threat_id = "2147888289"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".CreateObject(\"WS\" & lz & \"cript.Sh\" & lz & \"ell\").Run" ascii //weight: 1
        $x_1_2 = " Environ(\"LocalAppData\") & \"\\list.xsl\"" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"Adod\" & \"b.Stre\" & \"am\")" ascii //weight: 1
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-26] 2c 20 22 3a 22 2c 20 22 24 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Obfuse_SIT_2147898461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Obfuse.SIT!MTB"
        threat_id = "2147898461"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "'zipPath = \"C:\\Program Files (x86)\\WinRAR\\winRaR.exe\" & \" x -ibck \" & Fname & \" *.* \" & ThisDocument.Path" ascii //weight: 1
        $x_1_2 = "oStream.SaveToFile ThisDocument.Path & \"\\\" & \"malicious.exe\", 2" ascii //weight: 1
        $x_1_3 = {72 65 74 76 61 6c 20 3d 20 53 68 65 6c 6c 28 46 6e 61 6d 65 2c 20 76 62 4d 69 6e 69 6d 69 7a 65 64 46 6f 63 75 73 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "oApp.NameSpace(fFolder).CopyHere oApp.NameSpace(fName).items" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


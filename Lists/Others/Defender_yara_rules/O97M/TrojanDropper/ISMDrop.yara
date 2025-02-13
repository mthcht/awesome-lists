rule TrojanDropper_O97M_ISMDrop_A_2147727317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/ISMDrop.A!dha"
        threat_id = "2147727317"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ISMDrop"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 20 22 20 2f 63 20 65 63 68 6f 20 70 6f 77 65 72 73 68 65 6c 6c 20 3e 20 22 20 26 20 22 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 [0-16] 20 26 20 43 68 72 28 33 34 29 2c 20 76 62 48 69 64 65 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 22 43 6f 70 79 2d 49 74 65 6d 20 22 20 26 20 43 68 72 28 33 39 29 20 26 20 22 25 46 69 6c 65 50 61 74 68 25 22 20 26 20 43 68 72 28 33 39 29 20 26 20 22 20 22 20 26 20 43 68 72 28 33 39 29 20 26 20 22 25 44 65 73 74 46 6f 6c 64 65 72 25 22 20 26 20 43 68 72 28 33 39 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 20 22 20 2f 63 20 22 20 26 20 [0-16] 20 26 20 22 20 22 20 26 20 [0-16] 2c 20 76 62 48 69 64 65 0d 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 53 70 6c 69 74 28 [0-16] 2c 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 29 0d 0a}  //weight: 1, accuracy: Low
        $x_1_5 = {20 3d 20 22 52 65 6d 6f 76 65 2d 49 74 65 6d 20 22 20 26 20 43 68 72 28 33 39 29 20 26 20 22 25 46 69 6c 65 25 22 20 26 20 43 68 72 28 33 39 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 74 20 [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 0d 0a}  //weight: 1, accuracy: Low
        $x_1_7 = {20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 54 6d 70 2e 64 6f 63 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_8 = " = Environ$(\"AppData\") & \"\\Base.txt\"" ascii //weight: 1
        $x_1_9 = " = Environ$(\"PUBLIC\") & \"\\Libraries\\servicereset.exe\"" ascii //weight: 1
        $x_1_10 = "Error while converting document. NSCocoaErrorDomain Code=3840 Unable to convert data to string around character 34" ascii //weight: 1
        $x_2_11 = {20 3d 20 22 24 44 41 54 41 20 3d 20 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 5b 49 4f 2e 46 69 6c 65 5d 3a 3a 52 65 61 64 41 6c 6c 54 65 78 74 28 27 25 42 61 73 65 25 27 29 29 3b 5b 69 6f 2e 66 69 6c 65 5d 3a 3a 57 72 69 74 65 41 6c 6c 42 79 74 65 73 28 27 [0-16] 27 2c 24 44 41 54 41 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 [0-16] 27 22 0d 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_O97M_ISMDrop_B_2147727318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/ISMDrop.B!dha"
        threat_id = "2147727318"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ISMDrop"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 54 6d 70 2e 64 6f 63 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = " = Environ$(\"AppData\") & \"\\Base.txt\"" ascii //weight: 1
        $x_1_3 = " = Environ$(\"AppData\") & \"\\AdobeAcrobatLicenseVerify.ps1\"" ascii //weight: 1
        $x_1_4 = " = Environ$(\"AppData\") & \"\\AdobeAcrobatLicenseVerify.vbs\"" ascii //weight: 1
        $x_1_5 = {20 3d 20 22 63 6f 70 79 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 [0-16] 20 26 20 43 68 72 28 33 34 29 20 26 20 22 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 [0-16] 20 26 20 43 68 72 28 33 34 29 0d 0a}  //weight: 1, accuracy: Low
        $x_1_6 = {20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 42 61 73 65 2e 74 78 74 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_7 = {20 3d 20 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 24 22 2c 20 22 22 29 0d 0a}  //weight: 1, accuracy: Low
        $x_1_8 = {63 6d 64 20 3d 20 22 53 65 74 20 6f 53 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 20 28 25 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 25 29 20 3a 20 6f 53 68 65 6c 6c 2e 72 75 6e 20 25 21 25 2c 30 2c 30 22 0d 0a}  //weight: 1, accuracy: High
        $x_1_9 = {63 6d 64 20 3d 20 52 65 70 6c 61 63 65 28 63 6d 64 2c 20 22 25 22 2c 20 43 68 72 28 33 34 29 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_10 = {63 6d 64 20 3d 20 52 65 70 6c 61 63 65 28 63 6d 64 2c 20 22 21 22 2c 20 76 62 73 29 0d 0a}  //weight: 1, accuracy: High
        $x_2_11 = {20 3d 20 53 70 6c 69 74 28 [0-16] 2c 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 20 26 20 43 68 72 28 [0-2] 29 29 0d 0a}  //weight: 2, accuracy: Low
        $x_2_12 = {22 4e 75 6c 6c 52 65 66 72 65 6e 63 65 64 45 78 63 65 70 74 69 6f 6e 21 20 65 72 72 6f 72 20 68 61 73 20 6f 63 63 75 72 72 65 64 20 69 6e 20 75 73 65 72 33 32 2e 64 6c 6c 20 62 79 20 30 78 33 32 65 66 32 31 32 31 22 0d 0a}  //weight: 2, accuracy: High
        $x_2_13 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 20 22 20 2f 63 20 65 63 68 6f 20 22 20 26 20 43 68 72 28 33 32 29 20 26 20 63 6d 64 20 26 20 43 68 72 28 33 32 29 20 26 20 22 20 3e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 [0-32] 20 26 20 43 68 72 28 33 34 29 2c 20 76 62 48 69 64 65 0d 0a}  //weight: 2, accuracy: Low
        $x_2_14 = {22 20 2f 63 20 22 20 26 20 22 53 63 68 54 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 53 43 20 4d 49 4e 55 54 45 20 2f 4d 4f 20 ?? 20 2f 54 4e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 [0-16] 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 20 2f 54 52 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 [0-48] 20 26 20 43 68 72 28 33 34 29 2c 20 76 62 48 69 64 65 0d 0a}  //weight: 2, accuracy: Low
        $x_2_15 = {20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 [0-32] 2e 70 73 31 22 0d 0a [0-16] 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 [0-32] 2e 76 62 73 22 0d 0a}  //weight: 2, accuracy: Low
        $x_2_16 = " = \"Set oShell = WScript.CreateObject (%WScript.Shell%) : oShell.run %cmd.exe /c Powershell -exec bypass -Windowstyle hidden -File ! %,0,0\"" ascii //weight: 2
        $x_2_17 = {20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c [0-32] 2e 70 73 31 22 0d 0a 53 65 74 20 [0-16] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 0d 0a 53 65 74 20 [0-16] 20 3d 20 [0-16] 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 [0-16] 2c 20 32 2c 20 54 72 75 65 29}  //weight: 2, accuracy: Low
        $x_2_18 = {53 65 74 20 [0-16] 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 65 63 74 69 6f 6e 73 28 69 6e 74 53 65 63 74 69 6f 6e 29 2e 48 65 61 64 65 72 73 28 69 6e 74 48 46 54 79 70 65 29 2e 52 61 6e 67 65 0d 0a 0c 00 66 2e 77 72 69 74 65 20 28 [0-16] 29 0d 0a 08 00 4e 65 78 74 20 69 6e 74 48 46 54 79 70 65 0d 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


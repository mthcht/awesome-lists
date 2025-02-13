rule TrojanDropper_MSIL_ISMAgent_A_2147727320_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/ISMAgent.A!dha"
        threat_id = "2147727320"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ISMAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\runlog*" ascii //weight: 1
        $x_1_2 = "File Downloaded successfully" ascii //weight: 1
        $x_1_3 = "-c  SampleDomain.com -m scheduleminutes" ascii //weight: 1
        $x_1_4 = ".msoffice365update.com" ascii //weight: 1
        $x_1_5 = "cmd /c schtasks /query /tn TimeUpdate > NUL 2>&1 || schtasks /create /sc minute /mo 0003 /tn TimeUpdate /tr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_ISMAgent_A_2147727320_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/ISMAgent.A!dha"
        threat_id = "2147727320"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ISMAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 30 38 6c 58 25 30 34 68 58 25 30 34 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 25 30 32 68 68 58 00 2f}  //weight: 1, accuracy: High
        $x_1_2 = {63 6d 64 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 71 75 65 72 79 20 2f 74 6e 20 54 69 6d 65 55 70 64 61 74 65 20 3e 20 4e 55 4c 20 32 3e 26 31 20 7c 7c 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 [0-5] 20 2f 74 6e 20 54 69 6d 65 55 70 64 61 74 65 20 2f 74 72 20 22 5c 22}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 00 00 7c 7c 00 00 2e 64 2e 00 6e 2e 00 00 2e 66 2e 00 77 77 77 2e 00 00 00 00 2e 72 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 25 25 25 00 00 00 00 5c 22 22 00 2e [0-32] 00 5e 5e 5e 5e 5e 5e}  //weight: 1, accuracy: Low
        $x_1_5 = {5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 5e 00 00 00 00 48 65 6c 70}  //weight: 1, accuracy: High
        $x_1_6 = {48 65 6c 70 00 00 00 00 75 73 61 67 65 3a [0-16] 2d 63 20 20 53 61 6d 70 6c 65 44 6f 6d 61 69 6e 2e 63 6f 6d 20 2d 6d 20 73 63 68 65 64 75 6c 65 6d 69 6e 75 74 65 73 0a 0a 00}  //weight: 1, accuracy: Low
        $x_1_7 = {72 62 00 00 77 62 00 00 6f 75 74 2e 65 78 65 00 57 61 72 6e 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 21 21 21 20 63 61 6e 20 6e 6f 74 20 63 72 65 61 74 65 20 6f 75 74 70 75 74 20 66 69 6c 65 20 21 21 21 0a 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 20 2d 6d 00 20 2d 63 00 25 30 34 64 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 53 75 63 63 65 73 73 00 [0-8] 6f 6e 66 69 67 75 72 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 0a 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {61 6e 20 6e 6f 74 20 62 65 20 63 6f 6e 66 69 67 75 72 65 64 0a 00 00 [0-3] 77 77 77 00 68 74 74 70 3a 2f 2f 00}  //weight: 1, accuracy: Low
        $x_1_12 = {68 74 74 70 3a 2f 2f 00 63 61 6e 20 6e 6f 74 20 73 70 65 63 69 66 79 20 63 6f 6d 70 20 6e 61 6d 65 21 21 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 63 61 6e 20 6e 6f 74 20 73 70 65 63 69 66 79 20 75 73 65 72 6e 61 6d 65 21 21 00 00 5c 00 00 00 61 63 74 69 6f 6e 32 2f 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 28 00 00 00 00 75 70 6c 6f 61 64 2f 00}  //weight: 1, accuracy: High
        $x_1_15 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 61 2e 61 22 0d 0a 0d 0a 00 0d 0a 2d 2d 6d 79 62 6f 75 6e 64 61 72 79 2d 2d 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 64 6f 6e 65 00 00 00 00 73 65 72 76 65 72 20 72 65 73 70 6f 6e 64 20 77 69 74 68 20 65 72 72 6f 72 0a 00}  //weight: 1, accuracy: High
        $x_1_17 = {5c 72 75 6e 6c 6f 67 2a 00 00 00 00 5c 72 75 6e 6c 6f 67 00 2e 74 6d 70 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 00 00 29 20 3e 20 22 00 00 00 72 65 73 70 6f 6e 73 65 2f 00 00 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 46 69 6c 65 20 44 6f 77 6e 6c 6f 61 64 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 0a 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_20 = "C:\\Users\\Ross\\Documents\\Visual Studio 2015\\Projects\\Win32Project1\\Release\\Win32Project1.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}


rule Ransom_MSIL_Crypute_A_2147716312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.A"
        threat_id = "2147716312"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cuteRansomware" wide //weight: 1
        $x_1_2 = "!!!.txt" wide //weight: 1
        $x_1_3 = "____@gmail.com" wide //weight: 1
        $x_2_4 = "://docs.google.com/forms/d/1z_ZmpdVCJkn9Iaq-bQhjc9Z3LOBClNW0mu5wVINBK1s/formResponse" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Crypute_B_2147716546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.B"
        threat_id = "2147716546"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!! DECRYPT MY FILES !!.vbs" wide //weight: 1
        $x_1_2 = "/%21%21+DECRYPT+MY+FILES+%21%21.vbs" wide //weight: 1
        $x_1_3 = "\\razydecrypt.jpg" wide //weight: 1
        $x_1_4 = "Your documtes,photos,databases and other important files have been encrypted!" wide //weight: 1
        $x_1_5 = "getRandomFileName" wide //weight: 1
        $x_1_6 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~=!@#$%^&*()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Crypute_C_2147716550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.C"
        threat_id = "2147716550"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 61 6e 73 6f 6d 77 61 72 65 2e [0-32] 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = {41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5a 00 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 30 00 7e 00 3d 00 21 00 40 00 23 00 24 00 25 00 5e 00 26 00 2a 00 28 00 29 00 [0-32] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = "HitlerRansomware_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_MSIL_Crypute_D_2147717433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.D!bit"
        threat_id = "2147717433"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.diaochapai.com/survey/" wide //weight: 2
        $x_1_2 = "\\\\sendBack_RSAkey.ckt" wide //weight: 1
        $x_1_3 = "\\\\secretAES_RSAed_base64ed.ckt" wide //weight: 1
        $x_1_4 = "\\cke.cke" wide //weight: 1
        $x_1_5 = "imugf@outlook.com" wide //weight: 1
        $x_1_6 = "\\Ransomware\\Ransomware\\obj\\Debug\\R.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Crypute_E_2147722549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.E!bit"
        threat_id = "2147722549"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 61 6e 73 6f 6d 77 61 72 65 2e [0-32] 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = "Your computer has been hacked" wide //weight: 1
        $x_1_3 = "You will have to enter your credit card number" wide //weight: 1
        $x_1_4 = "KeyboardHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Crypute_PA_2147755456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.PA!MTB"
        threat_id = "2147755456"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 61 6e 73 6f 6d 77 61 72 65 2e [0-32] 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = "$2d4e22e5-8d86-4782-b0b7-559862d13524" ascii //weight: 1
        $x_1_3 = "Saher Blue Eagle Ransomware.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Crypute_PA_2147755456_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.PA!MTB"
        threat_id = "2147755456"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hacker2" wide //weight: 1
        $x_1_2 = ".fucked" wide //weight: 1
        $x_1_3 = "FucktheSystem" wide //weight: 1
        $x_1_4 = "YOU ARE HACKED WITH COBRA RANSOMWARE" wide //weight: 1
        $x_1_5 = {5c 43 4f 42 52 41 5c 43 4f 42 52 41 5c [0-32] 5c 43 4f 42 52 41 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Crypute_PB_2147766011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.PB!MTB"
        threat_id = "2147766011"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\FILES ENCRYPTED.txt" wide //weight: 1
        $x_1_2 = "SINGLE_INSTANCE_APP_MUTEX" wide //weight: 1
        $x_1_3 = "].crazy" wide //weight: 1
        $x_1_4 = ".encrypt" wide //weight: 1
        $x_1_5 = "http://crazycrypt.store/requests" wide //weight: 1
        $x_1_6 = "/write.php" wide //weight: 1
        $x_1_7 = "all your data has been locked us" wide //weight: 1
        $x_1_8 = "crazydecrypt@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Crypute_PC_2147766206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypute.PC!MTB"
        threat_id = "2147766206"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypute"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FucktheSystem" wide //weight: 1
        $x_1_2 = ".fucked" wide //weight: 1
        $x_1_3 = "Encryption Complete" wide //weight: 1
        $x_1_4 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_5 = "\\Ransomware21.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


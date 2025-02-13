rule Ransom_Win32_Crystalcrypt_A_2147726190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crystalcrypt.A"
        threat_id = "2147726190"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crystalcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {43 52 59 53 54 41 4c 43 52 59 50 54 20 52 41 4e 53 4f 4d 57 41 52 45 21 0d 0a 0d 0a 41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44}  //weight: 4, accuracy: High
        $x_4_2 = "YOU BECAME A VICTIM OF THE CRYSTALCRYPT RANSOMWARE!" ascii //weight: 4
        $x_4_3 = "PAY 0.17 BITCOINS TO THIS ADDRESS : 1LSgvYFY7SDNje2Mhsm51FxhqPsbvXEhpE" ascii //weight: 4
        $x_4_4 = "YOU CAN FIND THEM ON YOUR DESKTOP IN \"CRYSTALCRYPT_UNIQEID.TXT\"" ascii //weight: 4
        $x_4_5 = "Bitcoin Address: 14j51TreRGTeXqi9tJ8wCaf3Wseb1L21WM" ascii //weight: 4
        $x_4_6 = "CrystalCrypt_Recover_Instuctions.png" wide //weight: 4
        $x_1_7 = "A_Drive" ascii //weight: 1
        $x_1_8 = "B_Drive" ascii //weight: 1
        $x_1_9 = "D_Drive" ascii //weight: 1
        $x_1_10 = "E_Drive" ascii //weight: 1
        $x_1_11 = "F_Drive" ascii //weight: 1
        $x_1_12 = "G_Drive" ascii //weight: 1
        $x_1_13 = "H_Drive" ascii //weight: 1
        $x_1_14 = "I_Drive" ascii //weight: 1
        $x_1_15 = "J_Drive" ascii //weight: 1
        $x_1_16 = "K_Drive" ascii //weight: 1
        $x_1_17 = "L_Drive" ascii //weight: 1
        $x_1_18 = "M_Drive" ascii //weight: 1
        $x_1_19 = "N_Drive" ascii //weight: 1
        $x_1_20 = "O_Drive" ascii //weight: 1
        $x_1_21 = "P_Drive" ascii //weight: 1
        $x_1_22 = "Q_Drive" ascii //weight: 1
        $x_1_23 = "R_Drive" ascii //weight: 1
        $x_1_24 = "S_Drive" ascii //weight: 1
        $x_1_25 = "T_Drive" ascii //weight: 1
        $x_1_26 = "U_Drive" ascii //weight: 1
        $x_1_27 = "V_Drive" ascii //weight: 1
        $x_1_28 = "W_Drive" ascii //weight: 1
        $x_1_29 = "X_Drive" ascii //weight: 1
        $x_1_30 = "Y_Drive" ascii //weight: 1
        $x_1_31 = "Z_Drive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 24 of ($x_1_*))) or
            ((2 of ($x_4_*) and 20 of ($x_1_*))) or
            ((3 of ($x_4_*) and 16 of ($x_1_*))) or
            ((4 of ($x_4_*) and 12 of ($x_1_*))) or
            ((5 of ($x_4_*) and 8 of ($x_1_*))) or
            ((6 of ($x_4_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_MSIL_Solorigate_G_2147771190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Solorigate.G!dha"
        threat_id = "2147771190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Solorigate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CompileAssemblyFromSource" ascii //weight: 1
        $x_1_2 = "CreateCompiler" ascii //weight: 1
        $x_1_3 = "clazz" ascii //weight: 1
        $x_1_4 = "//NetPerfMon//images//NoLogo.gif" wide //weight: 1
        $x_1_5 = "App_Web_logoimagehandler.ashx.b6031896.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Solorigate_BR_2147771206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Solorigate.BR!dha"
        threat_id = "2147771206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Solorigate"
        severity = "Mid"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 00 30 00 37 00 4e 00 53 00 55 00 30 00 75 00 55 00 64 00 42 00 ?? 00 63 00 43 00 76 00 4b 00 7a 00 31 00 55 00 49 00 7a 00 38 00 77 00 7a 00 4e 00 6f 00 72 00 33 00 53 00 79 00 30 00 70 00 7a 00 79 00 2f 00 4b 00 64 00 6b 00 78 00 4a 00 4c 00 43 00 68 00 4a 00 4c 00 58 00 4c 00 4f 00 7a 00 30 00 76 00 4c 00 54 00 43 00 38 00 74 00 53 00 69 00 7a 00 4a 00 7a 00 4d 00 39 00 54 00 4b 00 4d 00 39 00 49 00 4c 00 55 00 70 00 56 00 38 00 41 00 78 00 77 00 7a 00 55 00 74 00 4d 00 79 00 6b 00 6c 00 4e 00 73 00 53 00 30 00 70 00 4b 00 6b 00 30 00 46 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {63 00 30 00 6b 00 74 00 54 00 69 00 37 00 4b 00 4c 00 43 00 6a 00 ?? 00 7a 00 4d 00 38 00 44 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_3 = {38 00 33 00 56 00 30 00 64 00 6b 00 78 00 4a 00 4b 00 55 00 6f 00 ?? 00 4c 00 67 00 59 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_4 = {63 00 2f 00 46 00 77 00 44 00 6e 00 44 00 4e 00 53 00 30 00 7a 00 ?? 00 53 00 55 00 30 00 42 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_5 = {63 00 2f 00 46 00 77 00 44 00 67 00 68 00 4f 00 4c 00 53 00 70 00 ?? 00 4c 00 51 00 49 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_6 = {63 00 2f 00 45 00 4c 00 39 00 73 00 67 00 76 00 4c 00 76 00 46 00 4c 00 ?? 00 45 00 30 00 46 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_7 = {63 00 2f 00 45 00 4c 00 64 00 73 00 6e 00 50 00 54 00 63 00 7a 00 4d 00 43 00 ?? 00 35 00 4e 00 53 00 38 00 75 00 73 00 43 00 45 00 35 00 4e 00 4c 00 45 00 72 00 4f 00 38 00 43 00 39 00 4b 00 53 00 53 00 30 00 43 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_8 = {63 00 2f 00 45 00 4c 00 44 00 6b 00 34 00 74 00 4b 00 6b 00 73 00 74 00 43 00 6b 00 ?? 00 4e 00 4c 00 45 00 72 00 4f 00 38 00 43 00 39 00 4b 00 53 00 53 00 30 00 43 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_9 = {38 00 77 00 78 00 77 00 54 00 45 00 6b 00 70 00 53 00 ?? 00 30 00 75 00 42 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_10 = {38 00 77 00 77 00 49 00 4c 00 6b 00 33 00 4b 00 53 00 ?? 00 30 00 42 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_11 = {63 00 30 00 6c 00 4e 00 53 00 79 00 7a 00 4e 00 4b 00 66 00 45 00 4d 00 ?? 00 45 00 38 00 73 00 53 00 53 00 31 00 50 00 72 00 41 00 51 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_12 = {43 00 30 00 37 00 4e 00 53 00 55 00 30 00 75 00 55 00 64 00 42 00 ?? 00 63 00 43 00 76 00 4b 00 7a 00 31 00 55 00 49 00 7a 00 38 00 77 00 7a 00 4e 00 6f 00 72 00 33 00 4c 00 30 00 67 00 74 00 53 00 69 00 7a 00 4a 00 7a 00 45 00 73 00 50 00 72 00 69 00 77 00 75 00 53 00 63 00 30 00 46 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_13 = {63 00 30 00 34 00 73 00 4b 00 4d 00 6e 00 ?? 00 7a 00 77 00 4d 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_14 = {38 00 77 00 39 00 32 00 4c 00 45 00 72 00 4f 00 79 00 43 00 ?? 00 4a 00 54 00 53 00 34 00 70 00 4c 00 55 00 6f 00 46 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_15 = {38 00 38 00 77 00 72 00 4c 00 6b 00 6e 00 4d 00 79 00 58 00 ?? 00 4a 00 4c 00 45 00 6b 00 46 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_16 = {38 00 79 00 39 00 4b 00 54 00 38 00 7a 00 4c 00 72 00 45 00 ?? 00 73 00 79 00 63 00 7a 00 50 00 41 00 77 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_17 = {43 00 30 00 70 00 4e 00 7a 00 79 00 77 00 75 00 53 00 53 00 ?? 00 4b 00 54 00 51 00 6b 00 74 00 54 00 69 00 30 00 43 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_18 = {43 00 30 00 73 00 74 00 4b 00 73 00 ?? 00 4d 00 7a 00 77 00 4d 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_19 = {69 00 33 00 61 00 4e 00 56 00 61 00 67 00 32 00 71 00 46 00 57 00 6f 00 ?? 00 67 00 52 00 69 00 6f 00 31 00 6f 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_20 = {38 00 2f 00 42 00 32 00 6a 00 59 00 7a 00 33 00 38 00 58 00 64 00 32 00 ?? 00 49 00 6e 00 33 00 64 00 58 00 54 00 32 00 38 00 50 00 52 00 7a 00 6a 00 51 00 6e 00 32 00 64 00 77 00 73 00 4a 00 64 00 77 00 78 00 79 00 6a 00 66 00 48 00 4e 00 54 00 43 00 37 00 4b 00 4c 00 38 00 35 00 50 00 4b 00 34 00 6c 00 78 00 4c 00 71 00 6f 00 73 00 4b 00 4d 00 6c 00 50 00 4c 00 30 00 6f 00 73 00 79 00 4b 00 67 00 45 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_21 = {38 00 30 00 31 00 4d 00 7a 00 73 00 6a 00 4d 00 53 00 33 00 ?? 00 76 00 7a 00 55 00 77 00 42 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_22 = {4d 00 7a 00 54 00 51 00 ?? 00 30 00 4d 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_23 = {4d 00 7a 00 49 00 31 00 31 00 54 00 4d 00 ?? 00 51 00 51 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_24 = {4d 00 7a 00 51 00 33 00 30 00 6a 00 4d 00 30 00 ?? 00 7a 00 50 00 51 00 4d 00 77 00 41 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_25 = {4d 00 7a 00 49 00 31 00 31 00 54 00 4d 00 79 00 ?? 00 64 00 41 00 44 00 51 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_26 = {4d 00 37 00 51 00 30 00 30 00 6a 00 4d 00 30 00 ?? 00 39 00 41 00 7a 00 30 00 44 00 4d 00 41 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_27 = {4d 00 7a 00 49 00 31 00 31 00 54 00 ?? 00 43 00 59 00 67 00 4d 00 39 00 41 00 77 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_28 = {4d 00 7a 00 49 00 79 00 30 00 54 00 ?? 00 41 00 51 00 51 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_29 = {4d 00 7a 00 49 00 78 00 30 00 41 00 4e 00 ?? 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_30 = {53 00 30 00 73 00 32 00 4d 00 4c 00 43 00 ?? 00 41 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_31 = {53 00 30 00 73 00 31 00 4d 00 4c 00 43 00 ?? 00 41 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_32 = {53 00 30 00 74 00 4e 00 4e 00 72 00 43 00 ?? 00 41 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_33 = {53 00 30 00 74 00 4c 00 4e 00 72 00 43 00 ?? 00 41 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_34 = {53 00 30 00 73 00 7a 00 4d 00 4c 00 ?? 00 79 00 41 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_35 = {4d 00 7a 00 48 00 55 00 73 00 7a 00 44 00 ?? 00 4d 00 7a 00 53 00 31 00 31 00 44 00 4d 00 41 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_36 = {4d 00 7a 00 49 00 31 00 31 00 54 00 4f 00 ?? 00 59 00 67 00 4d 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_37 = {4d 00 7a 00 66 00 52 00 4d 00 7a 00 51 00 ?? 00 30 00 54 00 4d 00 79 00 30 00 54 00 4d 00 41 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_38 = {4d 00 7a 00 49 00 31 00 31 00 54 00 4d 00 43 00 59 00 ?? 00 4d 00 4c 00 50 00 51 00 4d 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_39 = {4d 00 7a 00 51 00 31 00 30 00 54 00 4d 00 30 00 ?? 00 4e 00 41 00 7a 00 4e 00 44 00 48 00 51 00 4d 00 77 00 41 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_40 = {4d 00 7a 00 49 00 30 00 31 00 7a 00 4d 00 30 00 ?? 00 39 00 59 00 7a 00 31 00 7a 00 4d 00 41 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_41 = {4d 00 7a 00 4c 00 51 00 4d 00 7a 00 51 00 ?? 00 30 00 41 00 4e 00 43 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_42 = {4d 00 7a 00 49 00 31 00 31 00 54 00 4d 00 79 00 4e 00 ?? 00 45 00 7a 00 30 00 44 00 4d 00 41 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_43 = {73 00 7a 00 54 00 54 00 4d 00 7a 00 62 00 55 00 ?? 00 7a 00 51 00 33 00 30 00 6a 00 4d 00 41 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_44 = {4d 00 7a 00 51 00 32 00 31 00 44 00 4d 00 79 00 73 00 74 00 ?? 00 7a 00 4e 00 4e 00 49 00 7a 00 41 00 41 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_45 = {4d 00 7a 00 49 00 31 00 31 00 54 00 4d 00 43 00 59 00 79 00 ?? 00 39 00 41 00 77 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_46 = {4d 00 7a 00 51 00 78 00 30 00 62 00 4d 00 77 00 30 00 ?? 00 4d 00 79 00 4d 00 74 00 4d 00 7a 00 41 00 41 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_47 = {73 00 39 00 41 00 7a 00 74 00 4e 00 41 00 7a 00 4e 00 ?? 00 48 00 52 00 4d 00 77 00 41 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_48 = {4d 00 7a 00 49 00 31 00 31 00 54 00 4d 00 43 00 ?? 00 78 00 4d 00 39 00 41 00 77 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_49 = {4d 00 37 00 54 00 51 00 4d 00 7a 00 51 00 32 00 30 00 41 00 ?? 00 43 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_50 = {4d 00 7a 00 66 00 55 00 4d 00 7a 00 51 00 31 00 ?? 00 6a 00 4d 00 31 00 31 00 6a 00 4d 00 41 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_51 = {73 00 37 00 54 00 55 00 4d 00 37 00 66 00 55 00 4d 00 ?? 00 41 00 7a 00 41 00 41 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_52 = {73 00 7a 00 44 00 58 00 4d 00 7a 00 4b 00 32 00 30 00 4c 00 4d 00 ?? 00 30 00 44 00 4d 00 41 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_53 = {4d 00 37 00 53 00 30 00 31 00 44 00 4d 00 79 00 4d 00 ?? 00 51 00 7a 00 4e 00 44 00 54 00 58 00 4d 00 77 00 41 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_54 = {4d 00 37 00 51 00 77 00 30 00 54 00 4d 00 33 00 30 00 ?? 00 50 00 51 00 4d 00 77 00 41 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_55 = {30 00 37 00 44 00 50 00 31 00 4e 00 53 00 49 00 6a 00 ?? 00 76 00 55 00 72 00 59 00 71 00 74 00 69 00 64 00 50 00 55 00 4b 00 45 00 6b 00 74 00 4c 00 6f 00 48 00 7a 00 56 00 54 00 51 00 42 00 00}  //weight: 10, accuracy: Low
        $x_10_56 = {30 00 37 00 44 00 50 00 31 00 4e 00 51 00 6f 00 7a 00 73 00 39 00 ?? 00 4c 00 43 00 72 00 50 00 7a 00 45 00 73 00 70 00 31 00 67 00 51 00 41 00 00}  //weight: 10, accuracy: Low
        $x_10_57 = {43 00 30 00 6f 00 74 00 79 00 43 00 38 00 71 00 43 00 55 00 38 00 ?? 00 53 00 63 00 35 00 49 00 4c 00 51 00 70 00 4b 00 4c 00 53 00 6d 00 71 00 42 00 41 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_58 = {43 00 30 00 6f 00 74 00 79 00 43 00 38 00 71 00 43 00 55 00 38 00 73 00 53 00 ?? 00 35 00 49 00 4c 00 51 00 72 00 49 00 4c 00 79 00 34 00 70 00 79 00 4d 00 39 00 4c 00 42 00 51 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_59 = {53 00 79 00 7a 00 49 00 31 00 43 00 76 00 4f 00 7a 00 30 00 6b 00 ?? 00 4b 00 73 00 2f 00 4d 00 53 00 79 00 6e 00 57 00 53 00 38 00 37 00 50 00 42 00 51 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_60 = {53 00 79 00 77 00 72 00 4c 00 73 00 74 00 4e 00 7a 00 73 00 6b 00 ?? 00 54 00 64 00 46 00 4c 00 7a 00 73 00 38 00 46 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_61 = {53 00 79 00 77 00 6f 00 4b 00 4b 00 37 00 4d 00 53 00 39 00 ?? 00 4e 00 4c 00 4d 00 67 00 45 00 41 00 41 00 3d 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_62 = {53 00 79 00 33 00 56 00 4c 00 55 00 38 00 ?? 00 4c 00 74 00 45 00 31 00 42 00 41 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_63 = {4b 00 79 00 33 00 57 00 4c 00 55 00 38 00 ?? 00 4c 00 74 00 45 00 31 00 41 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_64 = {4b 00 79 00 33 00 57 00 54 00 55 00 30 00 73 00 4c 00 ?? 00 45 00 31 00 42 00 41 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_65 = {4b 00 79 00 33 00 57 00 54 00 55 00 30 00 73 00 4c 00 ?? 00 45 00 31 00 41 00 67 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
        $x_10_66 = {4d 00 37 00 55 00 77 00 54 00 6b 00 6d 00 30 00 4e 00 44 00 ?? 00 56 00 4e 00 54 00 4e 00 4b 00 54 00 4e 00 4d 00 31 00 4e 00 45 00 69 00 31 00 30 00 44 00 57 00 78 00 4e 00 44 00 ?? 00 53 00 54 00 62 00 52 00 49 00 4d 00 7a 00 49 00 77 00 54 00 54 00 59 00 33 00 53 00 6a 00 4a 00 4b 00 42 00 51 00 41 00 3d 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


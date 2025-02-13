rule Ransom_MSIL_Samas_A_2147708380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Samas.A"
        threat_id = "2147708380"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\Steam\\libav_h264-56.dll.crypt" wide //weight: 2
        $x_2_2 = {62 00 61 00 63 00 6b 00 75 00 70 00 [0-20] 2e 00 62 00 61 00 63 00 6b 00 [0-20] 2e 00 62 00 61 00 63 00 6b 00 75 00 70 00 64 00 62 00}  //weight: 2, accuracy: Low
        $x_2_3 = {73 00 70 00 69 00 [0-20] 73 00 70 00 66 00 [0-20] 73 00 61 00 76 00 [0-20] 73 00 69 00 6b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Samas_A_2147708380_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Samas.A"
        threat_id = "2147708380"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HELP_DECRYPT_YOUR_FILES" wide //weight: 1
        $x_1_2 = ".encryptedRSA" wide //weight: 1
        $x_1_3 = "Could not begin restart session.  Unable to determine file locker." wide //weight: 1
        $x_1_4 = "Could not list processes locking resource." wide //weight: 1
        $x_1_5 = "Key is not correct format :" wide //weight: 1
        $x_1_6 = {57 68 6f 49 73 4c 6f 63 6b 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_7 = {6d 79 65 65 6e 6e 63 63 00}  //weight: 1, accuracy: High
        $x_1_8 = "<recursivegetfiles>" ascii //weight: 1
        $x_1_9 = "E_N_C_1234" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_MSIL_Samas_A_2147708380_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Samas.A"
        threat_id = "2147708380"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "57006800610074002000680061007000700065006E0065006400200074006F00200079006F00750072002000660069006C00650073003F" wide //weight: 1
        $x_1_2 = "41006C006C00200079006F00750072002000660069006C0065007300200065006E00630072007900700074006500640020" wide //weight: 1
        $x_1_3 = "42006900740063006F0069006E00200050006500720048006F00730074" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_MSIL_Samas_B_2147709919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Samas.B"
        threat_id = "2147709919"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<MMtt_AeS_KeY_For_File>" wide //weight: 1
        $x_1_2 = "2E00760062002C002E00610073006D0078002C002E0063006F006E006600690067002C002E" wide //weight: 1
        $x_1_3 = "480045004C0050005F0044004500430052005900500054005F0059004F00550052005F00460049004C0045005300" wide //weight: 1
        $x_1_4 = "48004F0057005F0054004F005F0044004500430052005900500054005F00460049004C0045005300" wide //weight: 1
        $x_2_5 = "2E0065006E006300720079007000740065006400520053004100" wide //weight: 2
        $x_1_6 = "\\AdobeReder" wide //weight: 1
        $x_1_7 = "tasklist\", \"/v /fo csv" wide //weight: 1
        $x_1_8 = "<re_cu_rsi_vege_tfi_les>" ascii //weight: 1
        $x_2_9 = "loopf_orch_eckan_ddelsaaaam" ascii //weight: 2
        $x_1_10 = "fil_ec_reati_onind_eskt_op_us_ers_" ascii //weight: 1
        $x_1_11 = "en_cr_yptfun_cm_agic_" ascii //weight: 1
        $x_1_12 = "dire_c_toryy_ofdelll" ascii //weight: 1
        $x_1_13 = "che_cki_f_lock_fi_le" ascii //weight: 1
        $x_1_14 = "fil_ec_reati_onind_eskt_op_us_ers" ascii //weight: 1
        $x_1_15 = "\\BackupHomeDir" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Samas_C_2147710128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Samas.C"
        threat_id = "2147710128"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 13 7e 0b 00 00 04 73 ?? 00 00 0a 6f ?? 00 00 0a 07 17 58 0b 07 1f 12 32 e8 1f 1a 8d ?? 00 00 01 13 0b 11 0b 16 72 ?? ?? 00 70 a2 11 0b 17 72 ?? ?? 00 70 a2 11 0b 18 72 ?? ?? 00 70 a2 11 0b 19}  //weight: 5, accuracy: Low
        $x_1_2 = "</yeK>" wide //weight: 1
        $x_1_3 = "<QWERTYUIOPASDFGHJKLZX>" wide //weight: 1
        $x_1_4 = "</yeKdetpyrcnE>" wide //weight: 1
        $x_1_5 = "</htgneLeliFlanigirO>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Samas_D_2147719546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Samas.D"
        threat_id = "2147719546"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 05 9a 0c 08 20 80 00 00 00 28 59 00 00 0a 08 28 3e 00 00 0a 11 05 17 58 13 05}  //weight: 1, accuracy: High
        $x_1_2 = {00 09 53 00 41 00 4c 00 54 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Samas_D_2147719546_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Samas.D"
        threat_id = "2147719546"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "B917754BCFE717EB4F7CE04A5B11A6351EEC5015" ascii //weight: 2
        $x_2_2 = "ksdghksdghkddgdfgdfgfd" ascii //weight: 2
        $x_2_3 = "qwertyhgfgfddfhgfdfdgfdgdgd" ascii //weight: 2
        $x_2_4 = "qwertfdsdkkiuhgdgsdsfdsdf" ascii //weight: 2
        $x_2_5 = "ghtrfdfdewsdfgtyhgjgghfdg" ascii //weight: 2
        $x_2_6 = "osieyrgvbsgnhkflkstesadfakdhaksjfgyjqqwgjrwgehjgfdjgdffg" ascii //weight: 2
        $x_2_7 = "fgdfghhtrdsfghdghdfhdshshfhfdgh" ascii //weight: 2
        $x_2_8 = "hdfgkhioiugyfyghdseertdfygu" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Samas_D_2147719546_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Samas.D"
        threat_id = "2147719546"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdgasfse" ascii //weight: 1
        $x_1_2 = "doliohdyjkajd" ascii //weight: 1
        $x_2_3 = "zdsrfvdg23.exe" ascii //weight: 2
        $x_2_4 = "rock2.exe" ascii //weight: 2
        $x_2_5 = "egzertyuhfgdfhjs.exe" ascii //weight: 2
        $x_2_6 = "exturydtcfdg.exe" ascii //weight: 2
        $x_4_7 = "dllhgjdvdfgdf" ascii //weight: 4
        $x_4_8 = "dsjhfcgfnjsghfuytaweyajgshdfsdf" ascii //weight: 4
        $x_4_9 = "sjgfqjwgfsdfkasjbjfsjokhmgnhtgrfd" ascii //weight: 4
        $x_4_10 = "osieyrgvbsgnhkflkstesadfakdhaksjfgyjqqwgjrwgehjgfdjgdffg" ascii //weight: 4
        $x_8_11 = "*.stubbin" wide //weight: 8
        $x_8_12 = "*.berkshire" wide //weight: 8
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((4 of ($x_4_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 4 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}


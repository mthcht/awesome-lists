rule PWS_Win32_Mujormel_A_2147687578_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mujormel.A"
        threat_id = "2147687578"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mujormel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "65F16AFF6295DE6FC3C0177383F1097EF60E1706040E096288EC72F50938213FB245D3729" wide //weight: 10
        $x_1_2 = "jornbalsslx.hol.es/PostHot.php" wide //weight: 1
        $x_1_3 = "mudalogo@bol.com.br" wide //weight: 1
        $x_1_4 = "melhormusica2013@gmail.com" wide //weight: 1
        $x_1_5 = "lcbrodriguesfilhome@uol.com.br" wide //weight: 1
        $x_1_6 = "luisfilho67@gmail.com" wide //weight: 1
        $x_1_7 = "vememmiminfor@googlemail.com" wide //weight: 1
        $x_1_8 = "fhaezy25313113" wide //weight: 1
        $x_1_9 = "www.contagotas.com.br/contador.php" wide //weight: 1
        $x_1_10 = "YUQL23KL23DF90WI5E1JAS467N" wide //weight: 1
        $x_1_11 = "Numero de Serie esta errado, por favor, digite novamente" wide //weight: 1
        $x_1_12 = "BRADESCO Informa: Por favor, Digite sua senha de 4 digitos" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Mujormel_B_2147687582_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mujormel.B"
        threat_id = "2147687582"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mujormel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "3C26263B25588383EF2DA3879FDD1562EA1A1B0A18223DBE2DB749C254F36DF30F212FD77" wide //weight: 10
        $x_1_2 = "catitacatita@uol.com.br" wide //weight: 1
        $x_1_3 = "chupetainfo@gmail.com" wide //weight: 1
        $x_1_4 = "cainfo2014@gmail.com" wide //weight: 1
        $x_1_5 = "wandearsonlopes@uol.com.br" wide //weight: 1
        $x_1_6 = "lixoeletronico40@gmail.com" wide //weight: 1
        $x_1_7 = "CAIXA Informa: Por favor, Digite o Nome de Usuario" wide //weight: 1
        $x_1_8 = {48 00 53 00 42 00 43 00 20 00 2d 00 20 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 3a 00 20 00 43 00 50 00 46 00 20 00 69 00 6e 00 76 00 ef 00 bf 00 bd 00 6c 00 69 00 64 00 6f 00 2e 00}  //weight: 1, accuracy: High
        $x_1_9 = {6f 00 20 00 63 00 6f 00 6d 00 70 00 6f 00 73 00 74 00 61 00 20 00 70 00 6f 00 72 00 20 00 33 00 20 00 64 00 ef 00 bf 00 bd 00 67 00 69 00 74 00 6f 00 73 00 20 00 5b 00 20 00 36 00 39 00 20 00 5d 00 20 00 49 00 6e 00 63 00 6f 00 72 00 72 00 65 00 74 00 61 00 21 00}  //weight: 1, accuracy: High
        $x_1_10 = "YUQL23KL23DF90WI5E1JAS467N" wide //weight: 1
        $x_1_11 = "www.contagotas.com.br/contador.php" wide //weight: 1
        $x_1_12 = "BRADESCO Informa: Por favor, Digite sua senha de 4 digitos" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Mujormel_C_2147687651_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mujormel.C"
        threat_id = "2147687651"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mujormel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hdveravera2013@gmail.com" wide //weight: 2
        $x_2_2 = "malvina-maria@uol.com.br" wide //weight: 2
        $x_2_3 = "as102030" wide //weight: 2
        $x_1_4 = {48 00 53 00 42 00 43 00 20 00 2d 00 20 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 3a 00 20 00 43 00 50 00 46 00 20 00 69 00 6e 00 76 00 ef 00 bf 00 bd 00 6c 00 69 00 64 00 6f 00 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = "BRADESCO Informa: Por favor, Digite sua senha de 4 digitos" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Mujormel_D_2147688180_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mujormel.D"
        threat_id = "2147688180"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mujormel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "hdvera2013@gmail.com" wide //weight: 4
        $x_4_2 = "notificacao2013@gmail.com" wide //weight: 4
        $x_2_3 = "webct@uol.com.br" wide //weight: 2
        $x_2_4 = "qw102030" wide //weight: 2
        $x_2_5 = "1nt3rn3t.....:" wide //weight: 2
        $x_2_6 = "3ntr0n1c4....:" wide //weight: 2
        $x_2_7 = "Cart40.......:" wide //weight: 2
        $x_1_8 = "FlashPlayerUpdate" wide //weight: 1
        $x_1_9 = "senderedemail.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_FormBook_P_2147742959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.P!MTB"
        threat_id = "2147742959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 03 d9 73 ?? e8 ?? ?? ?? ?? 80 33 e9 41 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_YL_2147744178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.YL!MSR"
        threat_id = "2147744178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Codes\\Version3\\stub333\\Release\\stub333.pdb" ascii //weight: 1
        $x_1_2 = "Microsoft Office Word" wide //weight: 1
        $x_1_3 = "WinWord.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_MR_2147744812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.MR!MTB"
        threat_id = "2147744812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 8b 45 08 01 ?? 0f [0-2] 0f [0-2] 89 [0-2] 8b [0-2] 8b [0-2] 01 ?? 0f [0-2] 8b [0-2] 89 ?? 8b [0-2] 8b [0-2] 01 ?? 31 ?? 89 ?? 88 ?? 8b [0-2] 89 [0-2] 83 [0-3] 8b [0-2] 3b [0-2] 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_E_2147748721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.E!MTB"
        threat_id = "2147748721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 c1 92 ab 00 00 05 25 7f 00 00 48 f7 d3 81 e2 14 0c 01 00 f7 d1 58 b9 14 c4 00 00 4a 42 48 f7 d1 05 a2 66 00 00 41 25 8b 0a 01 00 3d b9 0a 00 00 74 06 ba 67 43 00 00 59 4b 5b 81 f1 81 f0 00 00 81 f1 b8 52 00 00 81 c1 a1 f6 00 00 c2 1b 1d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_E_2147748721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.E!MTB"
        threat_id = "2147748721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "darkick@mail.ru" ascii //weight: 3
        $x_3_2 = "[DarkTeam]" ascii //weight: 3
        $x_3_3 = "Darkick Commander v0.95" ascii //weight: 3
        $x_3_4 = "SNLSOSPURLGLPTVPLOV" ascii //weight: 3
        $x_3_5 = "WebSnow" ascii //weight: 3
        $x_3_6 = "WebFloralWhite" ascii //weight: 3
        $x_3_7 = "WebBlack" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_C_2147748737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.C!MTB"
        threat_id = "2147748737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 e9 de d1 00 00 f7 d0 81 e3 a2 ae 00 00 43 05 65 1b 01 00 81 e3 be 3b 00 00 81 c3 8b 0a 01 00 5a 81 ea 6c 2c 00 00 81 e1 41 0c 00 00 81 c2 40 54 00 00 25 56 40 00 00 81 f1 e9 5b 00 00 48 81 ea c8 e5 00 00 3d c9 55 00 00 74 12 49 5a 81 e1 6b 04 01 00 59 81 f2 d9 10 00 00 c2 6a 4c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_C_2147748737_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.C!MTB"
        threat_id = "2147748737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 04 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 04 0f f7 da f8 11 d1 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_YP_2147749947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.YP!MTB"
        threat_id = "2147749947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 02 83 45 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 45 ?? 41 81 7d [0-16] 8a 01 34 ?? 88 45 ?? 8b 55 ?? 8a 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_N_2147750090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.N!MTB"
        threat_id = "2147750090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 19 81 ff ?? ?? ?? ?? 81 fa}  //weight: 2, accuracy: Low
        $x_2_2 = {31 1c 10 81 ff ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 83 c2 04}  //weight: 2, accuracy: Low
        $x_1_3 = {89 04 1f 71}  //weight: 1, accuracy: High
        $x_3_4 = {35 a8 d6 00 6a eb}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_M_2147750132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.M!MTB"
        threat_id = "2147750132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Rakkerkn9.exe" wide //weight: 3
        $x_3_2 = "napalmbo.exe" wide //weight: 3
        $x_3_3 = "i6uEcyVc8htLeWUqvyZyemUaCO0HDZUYg9E237" ascii //weight: 3
        $x_3_4 = "Gm8kstT93If4xNF4Yh0Sl71xxn3jKgZ142" ascii //weight: 3
        $x_3_5 = "LnQHKvqgvez7aG9QW9" wide //weight: 3
        $x_3_6 = "zVS4Mypwy2M8O79sLNNMkQGdWvq2zsliZWXxgjw148" wide //weight: 3
        $x_3_7 = "fdcL16eRgRBYypY9vqxPz9Vd1ilLfd91" wide //weight: 3
        $x_3_8 = "kJXXwXPsuWSjBqAama" ascii //weight: 3
        $x_2_9 = "oBaseCodePageEncodingj" wide //weight: 2
        $x_2_10 = "ZgZ8zpKOWO5gD5X9byb8OZZP" ascii //weight: 2
        $x_2_11 = "u3QfUxLd2okDfyiZwv7r9FLb" ascii //weight: 2
        $x_2_12 = "VYcfcAcoWk" wide //weight: 2
        $x_2_13 = "lyMdlkJZ" wide //weight: 2
        $x_2_14 = "oX7gQIajnGOSMaxmYI" ascii //weight: 2
        $x_2_15 = "roN7ePvp7bTTArQwrL" ascii //weight: 2
        $x_2_16 = "UTQ1Av2WgsqRW0l5fc" ascii //weight: 2
        $x_2_17 = "yrXDpVdcuv" wide //weight: 2
        $x_2_18 = "MJsEBRNsoR.exe" wide //weight: 2
        $x_1_19 = "dKjgFiRZ" wide //weight: 1
        $x_1_20 = "LkR9M41JGjCHGefMFZs" ascii //weight: 1
        $x_1_21 = "Gs8LHszJHs" ascii //weight: 1
        $x_1_22 = "sBspKBs" ascii //weight: 1
        $x_1_23 = "KVee4dxOmAShBMUxpNF0QInZ" ascii //weight: 1
        $x_1_24 = "L51ErJqKbJ" wide //weight: 1
        $x_4_25 = "jkrgklrdjgkjsgjdrhlrkdlhdh" wide //weight: 4
        $x_1_26 = "pc1eOx2WJVV" ascii //weight: 1
        $x_4_27 = "DutjaHAjA0z2bWhulZUQYTWPV0R4D5Ukd2bbR5w4UpokinN" wide //weight: 4
        $x_1_28 = "elwkVCxKYpaQ" wide //weight: 1
        $x_3_29 = "ALFASTR.exe" wide //weight: 3
        $x_1_30 = "tswQIBEFSyt" wide //weight: 1
        $x_2_31 = "cVudjN4rR4ulZIP5T2" ascii //weight: 2
        $x_2_32 = "O7Fl0PxfjNqv9xsrO1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_H_2147750160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.H!MTB"
        threat_id = "2147750160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {ff 34 0f d9 d0}  //weight: 3, accuracy: High
        $x_3_2 = {31 34 24 d9 d0}  //weight: 3, accuracy: High
        $x_3_3 = {8f 04 08 39 db}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_K_2147750163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.K!MTB"
        threat_id = "2147750163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 04 1f 89}  //weight: 2, accuracy: High
        $x_1_2 = {b8 69 5d 3f 99}  //weight: 1, accuracy: High
        $x_3_3 = {81 f7 3a ac ce f1}  //weight: 3, accuracy: High
        $x_3_4 = {8b 34 0a 0f 64 d5 [0-65] 81 f6 [0-80] 89 34 08}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_BS_2147750180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BS!MTB"
        threat_id = "2147750180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 00 02 80 c7 45 ?? 0a 00 00 00 c7 45 ?? 04 00 02 80 c7 45 ?? 0a 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "VALfsGEgEKRNQ1CWl0yFL2JBTbZZvoyZCSPe159" wide //weight: 1
        $x_1_3 = "mOgekaC4cyFyffr1IxMxH143" wide //weight: 1
        $x_1_4 = "rp7kaXyXBQq1IQJupKlP4UB5pQd170" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BS_2147750180_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BS!MTB"
        threat_id = "2147750180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INDVENDINGERFRITTENDEBESVRLIGGJORTESLAAENBUSKENRAPUN" wide //weight: 1
        $x_1_2 = "EsN9SvHCfnmXzHPx1Ykk12cQnyclCU3fKeaU129" wide //weight: 1
        $x_1_3 = "protegeersaglahmostasehjortekalveneultimum" wide //weight: 1
        $x_1_4 = "DOGANASCHEDULIZEFORTYSKESOUTDWELLERFINNURRELAT" wide //weight: 1
        $x_1_5 = "ZWl36v4Mpp18" wide //weight: 1
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_R_2147750332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.R!MTB"
        threat_id = "2147750332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 f1 43 e2 db ec}  //weight: 1, accuracy: High
        $x_1_2 = {89 0c 18 39}  //weight: 1, accuracy: High
        $x_2_3 = {81 f1 d8 79 24 d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_S_2147750598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.S!MTB"
        threat_id = "2147750598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "w7XvT3eB2utpaF32" wide //weight: 3
        $x_3_2 = "ZGHNWbcYaabababYM" ascii //weight: 3
        $x_2_3 = "dagnybul" wide //weight: 2
        $x_3_4 = "v7qI6kYPQarAg8fmxDSgJ237" wide //weight: 3
        $x_3_5 = "Y8RJTcp4687zT9dbLLTLlbpawOkiO2" wide //weight: 3
        $x_2_6 = "xTB6VUdx3t2Q3VxWg6SDiYCxlLHeMa224" wide //weight: 2
        $x_3_7 = "yO9Kghg7nxW5JVDCx8" wide //weight: 3
        $x_3_8 = "Svart6.exe" wide //weight: 3
        $x_2_9 = "Officialese6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_T_2147750732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.T!MTB"
        threat_id = "2147750732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 0f 6e c6 [0-16] 66 0f 6e c9 [0-16] 66 0f ef c8 [0-16] 66 0f 7e c9 [0-16] 39 c1 0f 77 [0-16] 46 [0-16] ff 37 [0-16] 59}  //weight: 2, accuracy: Low
        $x_1_2 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_U_2147750824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.U!MTB"
        threat_id = "2147750824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jAHxB6aic2yPK95MpS6x5gUm315" wide //weight: 1
        $x_1_2 = "kdqF0DZF6125" wide //weight: 1
        $x_1_3 = "EtCes0mfY2QoX35YAnKh0mn0cSPU09Z34" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_V_2147750825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.V!MTB"
        threat_id = "2147750825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kdr2T71LBy9gHHHZEFyk73hGH84" wide //weight: 1
        $x_1_2 = "fHsx74CpJPOGAx8D7Va87Lt1iSnSiu0VIPugzUyj170" wide //weight: 1
        $x_1_3 = "Tp546gnRXdgjufwH77JNTSB4JFs4fR1esloL49oS188" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_W_2147750826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.W!MTB"
        threat_id = "2147750826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fbm5KcKLqiiT2N36caGe0oiMvDuHr4Lo57Y2zIg147" wide //weight: 1
        $x_1_2 = "CbcEKmg1elifRN6uqpv13" wide //weight: 1
        $x_1_3 = "WDDBhbETAWALhgGsoAZ1CnlQAnXxkZQV61Vun207" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_Y_2147750828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.Y!MTB"
        threat_id = "2147750828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 ff ff 75 f8 5a 30 02 ff 45 f8 49 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AA_2147750879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AA!MTB"
        threat_id = "2147750879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thoracoceloschisis" wide //weight: 1
        $x_1_2 = "symon" wide //weight: 1
        $x_1_3 = "suspected" wide //weight: 1
        $x_1_4 = "filiality" wide //weight: 1
        $x_1_5 = "Doubl" wide //weight: 1
        $x_1_6 = "Gs8LHszJHs" ascii //weight: 1
        $x_1_7 = "sBspKBs" ascii //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AD_2147751133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AD!MTB"
        threat_id = "2147751133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 58 c1 [0-16] 66 0f 74 c1 [0-16] 66 0f 6e e6 [0-16] 66 0f 6e e9 [0-16] 66 0f 57 ec [0-16] 66 0f 7e e9 [0-16] 39 c1 74}  //weight: 1, accuracy: Low
        $x_1_2 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AD_2147751133_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AD!MTB"
        threat_id = "2147751133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {38 1c 01 74 0e 40 3d 00 01 00 00 7c f3 8b 85 f4 fe fe ff 8a 84 05 fc fe ff ff 88 06 8b 85 f8 fe fe ff 46 4f}  //weight: 10, accuracy: High
        $x_10_2 = {55 8b ec 83 ec 20 a1 ?? ?? ?? ?? 33 c5 89 45 fc a1 ?? ?? ?? ?? 53 56 57 a8 01 75 17 83 c8 01 6a 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AE_2147751134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AE!MTB"
        threat_id = "2147751134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Prdikativintermessagederboendesindonevkk" wide //weight: 1
        $x_1_2 = "Opgangenesmarkedsop1" wide //weight: 1
        $x_1_3 = "Bdepraksisenserminoisspoonlikeshemitehy" wide //weight: 1
        $x_1_4 = "snodsjlsstor" wide //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AF_2147751135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AF!MTB"
        threat_id = "2147751135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 83 ec 18 c7 45 fc 00 00 00 00 c7 45 e8 00 00 00 00 6a 04 68 00 30 00 00 68 00 09 3d 00}  //weight: 5, accuracy: High
        $x_5_2 = {83 7d 0c 00 74 1a 8b 4d fc c6 01 00 8b 55 fc 83 c2 01 89 55 fc 8b 45 0c 83 e8 01 89 45 0c eb e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AF_2147751135_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AF!MTB"
        threat_id = "2147751135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 10 6a 00 8d 4d fc 51 53 8b f0 56 52 ff 15 ?? ?? ?? ?? 80 04 3e f1 47 3b fb}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AF_2147751135_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AF!MTB"
        threat_id = "2147751135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "V7xoQ8eiwdWyR8FetDrl8WVUzpmjv75" wide //weight: 2
        $x_2_2 = "haF0dU4j59YTzcA3mgiq8FhdJ7mOEv4rIC53" wide //weight: 2
        $x_1_3 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_4 = "YpXoJ1408581668" wide //weight: 1
        $x_1_5 = "aWXLT1002822895" wide //weight: 1
        $x_1_6 = "wzIe31160463407" wide //weight: 1
        $x_1_7 = "ebMUe2038935785" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_AG_2147751406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AG!MTB"
        threat_id = "2147751406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {66 0f 58 c1 [0-16] 66 0f 74 c1 [0-16] 66 0f 6e e6 [0-16] 66 0f 6e e9 [0-16] 0f 57 ec [0-16] 66 0f 7e e9 [0-16] 39 c1 74}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AH_2147751458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AH!MTB"
        threat_id = "2147751458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {88 14 08 8b 45 e4 8b 4d d4 8a 14 08 80 c2 01 88 14 08 8b 45 e4 8b 4d d4 0f b6 34 08 89 f3 83 f3 36 88 1c 08 8b 45 e4 8b 4d d4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AH_2147751458_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AH!MTB"
        threat_id = "2147751458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 d4 8b 52 04 89 14 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 89 4d cc ff d0 83 ec 1c}  //weight: 5, accuracy: High
        $x_5_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AH_2147751458_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AH!MTB"
        threat_id = "2147751458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {81 eb 86 d9 00 00 58 bb a2 ae 00 00 f7 d2 40 40 f7 d2 81 f3 96 24 01 00 81 eb f4 75 00 00 81 e1 d3 6f 00 00 b8 30 51 00 00 59 81 e1 c7 2d 01 00 48 3d 40 9c 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AH_2147751458_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AH!MTB"
        threat_id = "2147751458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 58 c1 [0-16] 66 0f 74 c1 [0-16] 66 0f 6e e6 [0-16] 66 0f 6e e9 [0-16] 0f 57 ec [0-16] 66 0f 7e e9 [0-16] 39 c1 [0-16] 0f 77 [0-16] 46 [0-16] 8b 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AH_2147751458_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AH!MTB"
        threat_id = "2147751458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "qutrblvhno" ascii //weight: 3
        $x_3_2 = "sgtyih" ascii //weight: 3
        $x_3_3 = "tzgyobzfq" ascii //weight: 3
        $x_3_4 = "ImmRegisterWordW" ascii //weight: 3
        $x_3_5 = "ImmGetConversionStatus" ascii //weight: 3
        $x_3_6 = "ImmDestroyContext" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AL_2147751610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AL!MTB"
        threat_id = "2147751610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "QxHHHksgB1qrcd9xfab4a248" wide //weight: 1
        $x_1_3 = "eXgCFpYDsHlXmDPSM5Dho2153" wide //weight: 1
        $x_1_4 = "ebvukrmbFoQZKRwZ103" wide //weight: 1
        $x_1_5 = "fmJSpTotadYoH122" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AM_2147751611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AM!MTB"
        threat_id = "2147751611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc}  //weight: 3, accuracy: High
        $x_3_2 = {89 45 f4 6a 40 68 00 30 00 00 8b 55 f4 52 6a 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AM_2147751611_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AM!MTB"
        threat_id = "2147751611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0}  //weight: 3, accuracy: High
        $x_3_2 = {83 c4 08 89 45 f0 6a 40 68 00 30 00 00 8b 4d f4}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AM_2147751611_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AM!MTB"
        threat_id = "2147751611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 00 8b 04 88 2d d6 4b 04 00 41}  //weight: 2, accuracy: High
        $x_2_2 = {88 04 33 43 81 fb 6c 07 00 00 7c ef}  //weight: 2, accuracy: High
        $x_2_3 = "SimpShanghai" ascii //weight: 2
        $x_2_4 = "Harquebuses" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AM_2147751611_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AM!MTB"
        threat_id = "2147751611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uibmcEOwQKOWrtg1egEMtpYOBAWyFMwGVeFRK65" wide //weight: 1
        $x_1_2 = "ojRtdXP2rPNF5tlOIKjTMRhg5XbcALahnwNWY206" wide //weight: 1
        $x_1_3 = "PaYNu4Rz8tNyWZHCGirIJnPX79UIZ234" wide //weight: 1
        $x_1_4 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AM_2147751611_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AM!MTB"
        threat_id = "2147751611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FtpCreateDirectoryA" ascii //weight: 1
        $x_1_2 = "FtpDeleteFileW" ascii //weight: 1
        $x_1_3 = "HttpSendRequestW" ascii //weight: 1
        $x_1_4 = "InternetCheckConnectionW" ascii //weight: 1
        $x_1_5 = "ResUtilGetAllProperties" ascii //weight: 1
        $x_1_6 = "ResUtilStopService" ascii //weight: 1
        $x_1_7 = "CertAddEncodedCertificateToSystemStoreW" ascii //weight: 1
        $x_1_8 = "CertDuplicateCertificateContext" ascii //weight: 1
        $x_1_9 = "CryptExportPublicKeyInfo" ascii //weight: 1
        $x_1_10 = "CryptGetOIDFunctionAddress" ascii //weight: 1
        $x_1_11 = "CryptMsgCountersignEncoded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AN_2147751612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AN!MTB"
        threat_id = "2147751612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8a 04 33 2c 33 34 1c 2c 64 34 03 2c 02 88 04 33 46 81 fe de 14 00 00 72 e7}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AN_2147751612_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AN!MTB"
        threat_id = "2147751612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0}  //weight: 3, accuracy: High
        $x_3_2 = {83 c4 08 8b f8 6a 40 68 00 30 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AN_2147751612_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AN!MTB"
        threat_id = "2147751612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 08 83 c0 01 89 45 08 8b 4d 08 0f be 11 85 d2 74 16 8b 45 fc c1 e0 05 03 45 fc 8b 4d 08 0f be 11 03 c2 89 45 fc eb d7}  //weight: 3, accuracy: High
        $x_3_2 = {89 4d f4 8b 55 f8 8b 45 08 03 42 24}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AN_2147751612_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AN!MTB"
        threat_id = "2147751612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VURDERINGSMANDENSVELSMAGENDELIGSYNLO" wide //weight: 1
        $x_1_2 = "Rektangeletslevitatedautotro6" wide //weight: 1
        $x_1_3 = "GLUCOSESFUTUROLOGISKESINVOLUTESOVERS" wide //weight: 1
        $x_1_4 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AO_2147751613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AO!MTB"
        threat_id = "2147751613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 01 88 45 ?? 8b 55 ?? 8a 45 ?? 88 02 b0 ?? 30 02 83 45 fc ?? 73 ?? e8 ?? ?? ?? ?? ff 45 ?? 41 81 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AP_2147751614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AP!MTB"
        threat_id = "2147751614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f0 99 b9 0c 00 00 00 f7 f9 8b 45 e4 0f b6 0c 10 8b 55 dc 03 55 f0 0f b6 02 33 c1 8b 4d dc 03 4d f0 88 01 eb}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 6a 40 68 00 30 00 00 8b 55 e0 52 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AP_2147751614_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AP!MTB"
        threat_id = "2147751614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 58 c1 [0-16] 66 0f 74 c1 [0-16] 66 0f 6e e6 [0-16] 66 0f 6e e9 [0-16] 0f 57 ec [0-16] 66 0f 7e e9 [0-16] 39 c1 [0-37] 0f 77 [0-16] 46 [0-21] 8b 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AQ_2147751815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AQ!MTB"
        threat_id = "2147751815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 02 ff 45 ?? ff 45 ?? 41 81 7d [0-16] 8a 01 34 ?? 88 45 ?? 8b 55 ?? 8a 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AQ_2147751815_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AQ!MTB"
        threat_id = "2147751815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 6a 0c 5f f7 ff 8b 7d 10 8a 82 [0-4] 30 04 39 41 3b cb 72}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 24 6a 40 68 00 30 00 00 53 56 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AW_2147751900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AW!MTB"
        threat_id = "2147751900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lOqXZSsr0IvNES4ntZdGwewTNX1EVwD45" wide //weight: 1
        $x_1_2 = "bvGfYsbQ2WZYhzhSwdt7Gq21fZDx2Vlb119" wide //weight: 1
        $x_1_3 = "JGtCg2LThNrnBJ8WdeR103" wide //weight: 1
        $x_1_4 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_5 = "b5Vo36fAiaUjbyShVGJjkaq184" wide //weight: 1
        $x_1_6 = "jdrIZ4uSM8iJBFQTYi541zbi267" wide //weight: 1
        $x_1_7 = "igtF8gfmcU3ZuJCnmltZ52" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FormBook_AY_2147751990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AY!MTB"
        threat_id = "2147751990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CqgrvpFq82u217" wide //weight: 1
        $x_1_2 = "countertermagentromanersba" wide //weight: 1
        $x_1_3 = "alannahmoise" wide //weight: 1
        $x_1_4 = "Sekseresinveiglementfer" wide //weight: 1
        $x_1_5 = "Abstraktionsniveauerneegobarthian6" wide //weight: 1
        $x_1_6 = "anmelderensbetndteskausalit" wide //weight: 1
        $x_1_7 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BA_2147752054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BA!MTB"
        threat_id = "2147752054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bygningssnedkerierbisulcrationalesnaboejendommengenetablerendeacad9" wide //weight: 1
        $x_1_2 = "Outjugglestylopodiapreimmunizationbrevaabnernefag8" wide //weight: 1
        $x_1_3 = "flydesprringsgrenadierialnetherlanderbesnrelsenskontroltasts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BB_2147752456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BB!MTB"
        threat_id = "2147752456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 ec 08 31 c9 89 45 e8 8b 45 e8 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {83 ec 14 31 c9 39 c1 0f 85 05 00 00 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BB_2147752456_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BB!MTB"
        threat_id = "2147752456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 37 04 5d 34 f6 fe c0 34 7e 2c 7d 88 04 37 46 3b f3 72}  //weight: 2, accuracy: High
        $x_2_2 = {6a 40 68 00 30 00 00 68 00 09 3d 00 33 f6 56 ff d7 85 c0 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BB_2147752456_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BB!MTB"
        threat_id = "2147752456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 7e da 81 [0-48] [0-48] 46 [0-48] 8b 17 [0-32] 0f 6e fe [0-37] [0-37] 0f 6e da [0-37] 0f ef df}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 7e da 66 [0-48] [0-48] 46 [0-48] 8b 17 [0-32] 0f 6e fe [0-37] [0-37] 0f 6e da [0-37] 0f ef df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FormBook_BC_2147752457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BC!MTB"
        threat_id = "2147752457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENDEAREDPATESOVERDELESBRLENESOVERNICENESSPOSEKIK" wide //weight: 1
        $x_1_2 = "Galanerneumloadregnvandsbrndesafirer" wide //weight: 1
        $x_1_3 = "RSONNRERNECYKELTRNESLIBBERSAUCEINSTILLERWEARIABLEGAARRAD" wide //weight: 1
        $x_1_4 = "voksnespneumatosisregnvejrsdagenesprintprob" wide //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BD_2147752458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BD!MTB"
        threat_id = "2147752458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RbZJK0sOjZFWVoWXAxjBCNPxDB9zJWo68" wide //weight: 1
        $x_1_2 = "RbZJK0sOjZFWVoWXAxjBCNPxDB9zJWo200" wide //weight: 1
        $x_1_3 = "ISf0IAbdkd97y59sDMy2LYlF5DMsPl7k173" wide //weight: 1
        $x_1_4 = "pJ5YD3cuDDYTwVAVa47AyXxnlqQzHQxXkNm100" wide //weight: 1
        $x_1_5 = "snY1C1UQsGuCSADRfl4N4etBPJ09WgXSgdKR17" wide //weight: 1
        $x_1_6 = "RpeBo3RmwHaYkCD4HITRQXmb2132" wide //weight: 1
        $x_1_7 = "ISf0IAbdkd97y59sDMy2LYlF5DMsPl7k172" wide //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BE_2147752459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BE!MTB"
        threat_id = "2147752459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BFC5G176" wide //weight: 1
        $x_1_2 = "ILXu2BbQbWeLqnDJcgCbZHa7CJxTPK123" wide //weight: 1
        $x_1_3 = "PJgTtIN4RYSplkGIwKLCBt3FWb0MUA7PY164" wide //weight: 1
        $x_1_4 = "NMhQCTxyhKCEeorbUN9wK0GFkwC195" wide //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BG_2147752515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BG!MTB"
        threat_id = "2147752515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf b2 46 8a 03 32 c2 88 01 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BJ_2147752634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BJ!MTB"
        threat_id = "2147752634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 c2 0f b7 c9 [0-37] [0-37] 46 [0-37] 8b 17 [0-32] [0-32] 0f 6e da [0-32] 31 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BK_2147752635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BK!MTB"
        threat_id = "2147752635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 0a f8 [0-48] 31 3c 24 [0-48] 8f 04 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BN_2147752823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BN!MTB"
        threat_id = "2147752823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zujLvgwMScM0niVy7julu5IflaP7lzzkFUUvOH7249" wide //weight: 1
        $x_1_2 = "han180" wide //weight: 1
        $x_1_3 = "Gs8LHszJHs" ascii //weight: 1
        $x_1_4 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BF_2147752850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BF!MTB"
        threat_id = "2147752850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8f 04 31 d9 [0-48] 8b 04 32 [0-48] bf [0-48] 31 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BO_2147752851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BO!MTB"
        threat_id = "2147752851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oIgFk0oDz39PUwtWw1jKvfmD232" wide //weight: 1
        $x_1_2 = "Rl1tP6121" wide //weight: 1
        $x_1_3 = "RSyub44" wide //weight: 1
        $x_1_4 = "nKmjhjbCmp172" wide //weight: 1
        $x_1_5 = "diUdOI136" wide //weight: 1
        $x_1_6 = "brugerorganisationens" ascii //weight: 1
        $x_1_7 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BP_2147752852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BP!MTB"
        threat_id = "2147752852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 c2 0f b7 [0-37] [0-16] 46 [0-37] ff 37 [0-37] [0-16] 0f 6e da [0-37] 31 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_BR_2147753093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BR!MTB"
        threat_id = "2147753093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PJHIbEhc9CYBPcExoCcD0iYdNzs8gMeVQsbeGWY103" wide //weight: 1
        $x_1_2 = "FvO7uEP253bsDlSWHNS8IaGaAQ0oA5RktD216" wide //weight: 1
        $x_1_3 = "EjAJpcNJBe33G934MDulyLYwnwoyFClaCDYx085" wide //weight: 1
        $x_1_4 = "Jo5XAu76FU5NcRWp0Aq4Vu2130" wide //weight: 1
        $x_1_5 = "WawKUO6102" wide //weight: 1
        $x_1_6 = "TAPzEs2OzZQpYvmTMy179" wide //weight: 1
        $x_1_7 = "r2H3XwqD8nUczSc45" wide //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_L_2147753532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.L!MTB"
        threat_id = "2147753532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 34 1f 62 95 40 3e}  //weight: 5, accuracy: High
        $x_5_2 = {78 38 31 34 1f c4 aa 3b 44}  //weight: 5, accuracy: High
        $x_2_3 = {8b 3c 0a 85 c9}  //weight: 2, accuracy: High
        $x_3_4 = {39 c9 31 3c 08}  //weight: 3, accuracy: High
        $x_2_5 = {8b 3c 0a f7 c2}  //weight: 2, accuracy: High
        $x_3_6 = {31 3c 08 81 fa}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_BU_2147753533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BU!MTB"
        threat_id = "2147753533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BnODs1mGrWeql4FYqUbxCVtV2cnmAgisYkJ4" wide //weight: 2
        $x_2_2 = "j3A7RteCaok4YK7pZQ135" wide //weight: 2
        $x_2_3 = "lM2wr4GfzYksJk2iBT4hD8BfmeBu1mb144" wide //weight: 2
        $x_2_4 = "csiNpEpEAcODm1fND7kIMk7nPhen7LUe15" wide //weight: 2
        $x_2_5 = "VdqzXORL1OudUH156" wide //weight: 2
        $x_2_6 = "or6soIIyutGeVW5QY39" wide //weight: 2
        $x_1_7 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_BV_2147753534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BV!MTB"
        threat_id = "2147753534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ht4aTC0wxKA9TdPKsNsWO7GW0gj8lF3fhj5xC2U196" wide //weight: 1
        $x_1_2 = "PPDFuJwvIXjVh138Bwy226kjwPRVnzZB204" wide //weight: 1
        $x_1_3 = "QYvxfCigX3pQLjSXb7zMcOx3225" wide //weight: 1
        $x_1_4 = "qoIILF9QksKx6KhYW5VdSqH183" wide //weight: 1
        $x_1_5 = "X93PkLj2RNyw4vC2BNjs2217" wide //weight: 1
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_SU_2147753579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.SU!MTB"
        threat_id = "2147753579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f 6e da 85 d2 eb 02 00 00 31 f1 85 db c3}  //weight: 3, accuracy: High
        $x_3_2 = {0f 6e da 66 81 fb 07 d4 31 f1 81 fa 45 26 3c 05 c3}  //weight: 3, accuracy: High
        $x_3_3 = {0f 6e da 81 fb 35 96 13 30 31 f1 85 db c3}  //weight: 3, accuracy: High
        $x_3_4 = {0f 6e da 81 ff 12 d3 36 44 31 f1 eb 05 00 00 00 00 00 66 85 c0}  //weight: 3, accuracy: High
        $x_1_5 = "iZTfaOn6Pq1Y85DHB05WhVLSLOh1zXnnI970" wide //weight: 1
        $x_1_6 = "PpWYH1KWZRl2h103" wide //weight: 1
        $x_1_7 = "tuRmhGG0i2FcrAe4tVejh8Wpw6gYo110" wide //weight: 1
        $x_1_8 = "EDxBN5NhGQ203" wide //weight: 1
        $x_1_9 = "AFpDmPGMcLOSLLXaUAYZ84lBf3E34" wide //weight: 1
        $x_1_10 = "TBrVzLunJ5vLDt234" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_ST_2147753586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.ST!MTB"
        threat_id = "2147753586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 6e da 85 c0 31 f1 eb 11 [0-24] 85 ff c3}  //weight: 2, accuracy: Low
        $x_2_2 = {0f 6e da 66 [0-6] 31 f1 66 [0-5] c3}  //weight: 2, accuracy: Low
        $x_1_3 = "fA38DllQYavJwbJufgYxYMGUDDGnYxrTfv226" wide //weight: 1
        $x_1_4 = "qvuvuH4z9hMob6QQ8u6W228" wide //weight: 1
        $x_1_5 = "JNIyvFOoJWj76ovanxnPJGCqk9LC7QFaY0cIZbg76" wide //weight: 1
        $x_1_6 = "lZ5ptpFlQ2RPAvzBLKO165" wide //weight: 1
        $x_1_7 = "zlbXDHGUDv8ad100" wide //weight: 1
        $x_1_8 = "FGMIeRQ07d1ZQdKU164bHLaR3N5ld172" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_SV_2147753664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.SV!MTB"
        threat_id = "2147753664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 6e da 85 ff 31 f1 66 81 fa db b0 c3}  //weight: 2, accuracy: High
        $x_2_2 = {0f 6e da 66 3d a8 b1 eb 0c [0-21] 31 f1 66 85 c0 c3}  //weight: 2, accuracy: Low
        $x_2_3 = {0f 6e da 85 d2 31 f1 eb 0d [0-21] 81 fb 64 58 dc bb c3}  //weight: 2, accuracy: Low
        $x_1_4 = "YNQLPjdc9J88z7g8C192" wide //weight: 1
        $x_1_5 = "xAlNXQeoAVkmaUr3fsE3DtnW6VEll5Nc199" wide //weight: 1
        $x_1_6 = "yMzb3igG5JsL76fVaB3QNR4Ajggb25" wide //weight: 1
        $x_1_7 = "treyhngelaasenesunderfram" wide //weight: 1
        $x_1_8 = "Doloressadolphbenevolistcobwe" wide //weight: 1
        $x_1_9 = "Injuryrowingsfodmiavetidsfl4" wide //weight: 1
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

rule Trojan_Win32_FormBook_BW_2147753801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BW!MTB"
        threat_id = "2147753801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BANQUETTEUNCUSTOMEDMORONISMCHARNE" wide //weight: 1
        $x_1_2 = "URETHRATRESIARECKONABLEINDSBNING" wide //weight: 1
        $x_1_3 = "habitreceptorerfletvrklymphadenect" wide //weight: 1
        $x_1_4 = "Dragtposerclappereddvrgeskikkels2" wide //weight: 1
        $x_1_5 = "omniscribentkursisterneforl" wide //weight: 1
        $x_1_6 = "Kalaazarsmrkeopklbedestankef" wide //weight: 1
        $x_1_7 = "ludbehandlboyseasterlingh" wide //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_SS_2147753828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.SS!MTB"
        threat_id = "2147753828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yMqj6z3z1T6I5u4HFoKNjWU228" wide //weight: 1
        $x_1_2 = "HTWD2xjSuRu8wB2jI16y0lFo3K187" wide //weight: 1
        $x_1_3 = "v9yJHbKsUIXCbRTZM9Z142" wide //weight: 1
        $x_1_4 = "eSvCfFRCfTO8TA4vu167" wide //weight: 1
        $x_1_5 = "JfnWDQYeMBmjYXMPliHHfn33" wide //weight: 1
        $x_5_6 = {51 8b 0f eb 01 ba eb 01 ff 6a 00 eb 01 ac eb 01 b0 89 0c 24 eb 01 02 eb 01 62 31 34 24 eb 01 f1 eb 01 09 59}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_SS_2147753828_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.SS!MTB"
        threat_id = "2147753828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EwyEfuybiDtBD2nRh5nB4WlkjeJGRXM5jNQ240" wide //weight: 1
        $x_1_2 = "K4nNV6Jz126" wide //weight: 1
        $x_1_3 = "Ue5v06e5nQD8HKBzMGt6ZRK2229" wide //weight: 1
        $x_1_4 = "pPcH3kKf8gHlbl00KgFZ4z6125" wide //weight: 1
        $x_1_5 = "eg51pm8ccd7LbEVdxEXjSZakbf100" wide //weight: 1
        $x_1_6 = "QCheNedi9QHcC1yLUzUQp3H3oxfCfCn187" wide //weight: 1
        $x_1_7 = {00 00 ff 37 eb 0c 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 00 8f 04 18 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_FormBook_SS_2147753828_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.SS!MTB"
        threat_id = "2147753828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f 6e da 66 85 c0 31 f1 85 d2 c3}  //weight: 3, accuracy: High
        $x_3_2 = {01 d3 81 ff 13 b4 89 b6 66 3d 1a 08 66 81 fa ee 32 09 0b 66 85 db eb 47}  //weight: 3, accuracy: High
        $x_1_3 = "vTLhPDHbbCY6uzA0M59bQhFIm168" wide //weight: 1
        $x_1_4 = "CS59PkGEzxYnRyvdiBv4xOmgS158" wide //weight: 1
        $x_1_5 = "fpthI4qOj5jBO54poEFWawMD6NVCd90" wide //weight: 1
        $x_1_6 = "UMHiGohvjQ7F49JwHSYLhDAz230" wide //weight: 1
        $x_1_7 = "JRfVP1zM8JQ0peCaODQlTQaJRKet8GlH58kW2H128" wide //weight: 1
        $x_1_8 = "B9dRDyJjnh50kwaxMktDz0DP9X222" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_SC_2147753829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.SC!MTB"
        threat_id = "2147753829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6e da 85 db 31 f1 85 c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {09 0b 66 81 [0-32] 83 c2 04 [0-32] 83 c7 04 66 [0-5] 85 d2}  //weight: 1, accuracy: Low
        $x_1_3 = "RGeqs2ZV0yckR1ZGYlb158" wide //weight: 1
        $x_1_4 = "c6EUph0yEg7dPrHpJvttGw0frjJ3kY9VBIpZaY1247" wide //weight: 1
        $x_1_5 = "tObLbSGtJthKU9U7e6yYBrqY7JqF7H129" wide //weight: 1
        $x_1_6 = "i5YNpYZ23b8ucqCDg1Omn4INXWvpoZvk9qgUWE2A207" wide //weight: 1
        $x_2_7 = {0f 6e da 85 ff 31 f1 3d 08 48 c9 b8 c3}  //weight: 2, accuracy: High
        $x_2_8 = {0f 6e da 66 85 c0 31 f1 66 81 ff 96 01 c3}  //weight: 2, accuracy: High
        $x_2_9 = {0f 6e da 66 3d 3a c6 31 f1 66 81 ff fc f8}  //weight: 2, accuracy: High
        $x_1_10 = "qLSSR7c4ZQSCTOf1jOCYy4efAFBVusXP21" wide //weight: 1
        $x_1_11 = "DwgMcsLuzZp8eyomfGJuHZ7HcqejJQ5zKKOoteA72" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_BX_2147753860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.BX!MTB"
        threat_id = "2147753860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 02 88 45}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 8a 55 ?? 33 c2 [0-32] [0-16] 8b 55 ?? 88 02 [0-32] ff 45 [0-16] ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_Q_2147753906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.Q!MTB"
        threat_id = "2147753906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 1c 08 80 33 c7 41 4a 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CA_2147754285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CA!MTB"
        threat_id = "2147754285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 45 f0 00 84 d7 17 8b 45 e4 89 45 f4 83 7d f0 00 74 16 8b 45 f4 c6 00 00 8b 45 f4 40 89 45 f4 8b 45 f0 48 89 45 f0 eb e4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CA_2147754285_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CA!MTB"
        threat_id = "2147754285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fb d9 58 00 00 74 0d c2 55 d0 c2 6b bc bb 87 49 00 00 5a 43 81 c2 4f 2f 01 00 81 eb 4f 77 01 00 05 5f 7a 01 00 b9 45 85 00 00 bb 5b 71 00 00 81 c1 a7 27 01 00 b9 3f 2c 01 00 5a f7 d0 81 e2 19 3d 01 00 4a c2 1f de 42 48 4a c2 1a ad}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CB_2147754286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CB!MTB"
        threat_id = "2147754286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {53 57 56 83 ec 0c 31 c0 89 44 24 04 6a 40 68 00 30 00 00 68 00 84 d7 17}  //weight: 5, accuracy: High
        $x_5_2 = {b9 00 7c 28 e8 c6 84 08 00 84 d7 17 00 41 75 f5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CC_2147754287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CC!MTB"
        threat_id = "2147754287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WA_VMSIB" ascii //weight: 3
        $x_3_2 = "Don HO don" ascii //weight: 3
        $x_3_3 = "Lexx@baklanov.net" ascii //weight: 3
        $x_3_4 = "Unable to kill process" ascii //weight: 3
        $x_3_5 = "Select a process to be killed" ascii //weight: 3
        $x_3_6 = "SysInfo v2.0 beta" ascii //weight: 3
        $x_3_7 = "CoTaskMemAlloc" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_PI_2147754453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.PI!MTB"
        threat_id = "2147754453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 33 d2 f7 f6 41 8a 82 ?? ?? ?? 00 30 81 ?? ?? ?? 00 3b cf 72 e9 8d 45 ?? 50 6a 40 57 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 8b 45 ?? ff d0}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 49 00 8a 10 40 84 d2 75 ?? 2b c7 8b f8 33 d2 8b c1 f7 f7 41 8a 92 ?? ?? ?? 00 30 54 31 ff 3b cb 72 ?? 8d 85 ?? ?? ff ff 50 6a 40 53 56 ff 15 ?? ?? ?? 00 8b 45 ?? ff d0}  //weight: 10, accuracy: Low
        $x_10_3 = {8d 70 01 eb 03 8d 49 00 8a 10 40 84 d2 75 f9 2b c6 8b f0 8b c1 33 d2 f7 f6 41 8a 82 ?? ?? ?? 00 30 44 39 ff 3b cb 72 ?? 8b 45 ?? ff d0 05 00 b8 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_4 = {6a 40 8b f0 53 56 89 75 08 ff 15 ?? ?? ?? 00 33 c9 85 db 74 ?? b8 ?? ?? ?? 00 8d 78 01 8a 10 40 84 d2 75 ?? 2b c7 8b f8 8b c1 33 d2 f7 f7 41 8a 82 ?? ?? ?? 00 30 44 31 ff 3b cb 72 ?? 8b 45 08 ff d0}  //weight: 10, accuracy: Low
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = {83 c4 04 e8 ?? ?? ?? 00 8b f8 33 c9 89 7d ?? 85 db 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_PJ_2147754454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.PJ!MTB"
        threat_id = "2147754454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 06 46 85 c0 74 28 bb 00 00 00 00 53 31 14 e4 5a 6a 08 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 57 83 e7 00 31 df 83 e0 00 31 f8 5f aa 49 75 cc}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 06 46 85 c0 74 24 bb 00 00 00 00 53 31 14 e4 5a 6a 08 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 53 8f 45 f8 ff 75 f8 58 aa 49 75 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FormBook_AR_2147754455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AR!MTB"
        threat_id = "2147754455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 06 46 84 c0 75 ?? 2b f2 8d a4 24 00 00 00 00 8b c1 33 d2 f7 f6 41 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 3b cf 72}  //weight: 2, accuracy: Low
        $x_1_2 = {8b c1 33 d2 f7 f6 41 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 3b cf 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_CE_2147754549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CE!MTB"
        threat_id = "2147754549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {85 db ff 31 [0-64] 31 f1 [0-100] 11 0c 10}  //weight: 12, accuracy: Low
        $x_1_2 = "n0tGbo6IvmC6JNdS47pYX80" wide //weight: 1
        $x_1_3 = "Slidbanernes9" wide //weight: 1
        $x_1_4 = "PORNOFILM" wide //weight: 1
        $x_1_5 = "EFTERSTRBELSERNES" wide //weight: 1
        $x_1_6 = "Forulykkelsers7" wide //weight: 1
        $x_1_7 = "HJTTALERKABINETTER" wide //weight: 1
        $x_1_8 = "SAMMENBLANDINGENS" wide //weight: 1
        $x_1_9 = "SbUjZacV115" wide //weight: 1
        $x_1_10 = "UDBYTTENOTAER" wide //weight: 1
        $x_1_11 = "substitutionsrettighedernes" wide //weight: 1
        $x_1_12 = "siksakkendes" wide //weight: 1
        $x_1_13 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_12_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_MK_2147754696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.MK!MSR"
        threat_id = "2147754696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 85 c0 33 0c 24 66 85 db 5e 85 d2 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CI_2147755562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CI!MTB"
        threat_id = "2147755562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "W8EfN4E5Ptdmuiz4jfDiBJicpXYlGlu6L94y7o112" wide //weight: 1
        $x_1_2 = "HSdZWdbiHdEMHYhlUVUgZoD21taopemw13" wide //weight: 1
        $x_1_3 = "xcoINiIbdN9h1lSbebfKRzu0nsTWni5vAgBR0D105" wide //weight: 1
        $x_1_4 = "JSzJq1F8tkyhQ0pcPeAsWqyb8Uch5FlMT68" wide //weight: 1
        $x_1_5 = "zyP1oBoxvy1stHDHRsQT6C5kBWOab34TJq90" wide //weight: 1
        $x_1_6 = "c5e9il8Ge6mGqdcSXv0LIkuHPpgveXy3DXfeBJ239" wide //weight: 1
        $x_1_7 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CJ_2147755632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CJ!MTB"
        threat_id = "2147755632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Graphiter4" wide //weight: 1
        $x_1_2 = "ecologically" wide //weight: 1
        $x_1_3 = "Undslippelse" wide //weight: 1
        $x_1_4 = "Opgavefordelingens8" wide //weight: 1
        $x_1_5 = "enhedsskolens" wide //weight: 1
        $x_1_6 = "Nonflu5" wide //weight: 1
        $x_1_7 = "LSNINGEN" wide //weight: 1
        $x_1_8 = "Automatisering" wide //weight: 1
        $x_1_9 = "dybbjergarterne" wide //weight: 1
        $x_1_10 = "mandsmod" wide //weight: 1
        $x_1_11 = "chickenbill" wide //weight: 1
        $x_1_12 = "Wadmal2" wide //weight: 1
        $x_1_13 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CM_2147755921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CM!MTB"
        threat_id = "2147755921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 74 11 83 7d fc 04 [0-32] c7 45 [0-32] 80 34 01 ?? ff 45 fc 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CO_2147755922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CO!MTB"
        threat_id = "2147755922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 1c 0f f7 [0-64] 31 f3 [0-200] 09 1c 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CP_2147756404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CP!MTB"
        threat_id = "2147756404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 14 30 83 f9 ?? 75 ?? 33 c9 eb ?? 41 40 3b c7 [0-21] 8a 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CQ_2147756478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CQ!MTB"
        threat_id = "2147756478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BESKYTTELSESOMRAADERNES" wide //weight: 1
        $x_1_2 = "Marsileaceous7" wide //weight: 1
        $x_1_3 = "beherskernes" wide //weight: 1
        $x_1_4 = "Transgressor" wide //weight: 1
        $x_1_5 = "ANTIBRIDAL" wide //weight: 1
        $x_1_6 = "lurifaks" wide //weight: 1
        $x_1_7 = "Brevdue" wide //weight: 1
        $x_1_8 = "KREDITGIVNINGEN" wide //weight: 1
        $x_1_9 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CR_2147756479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CR!MTB"
        threat_id = "2147756479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 02 ff 45 ?? 81 7d [0-48] [0-48] 8b 45 ?? 83 e0 [0-48] 8b 45 ?? 8a 80 [0-32] 34 ?? 8b 55 ?? 03 55 ?? 88 02 [0-48] 8b 45 ?? 8a 80 [0-32] 8b 55 ?? 03 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CR_2147756479_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CR!MTB"
        threat_id = "2147756479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Driftsforstyrrelsernes9" wide //weight: 1
        $x_1_2 = "Fremskridtspartiet7" wide //weight: 1
        $x_1_3 = "distributionsaftalen" wide //weight: 1
        $x_1_4 = "Parliamenter" wide //weight: 1
        $x_1_5 = "tekstmanipulationernes" wide //weight: 1
        $x_1_6 = "Adgangseksaminens8" wide //weight: 1
        $x_1_7 = "nonresolvability" wide //weight: 1
        $x_1_8 = "Decontrolled9" wide //weight: 1
        $x_1_9 = "Erindringsforskydningernes6" wide //weight: 1
        $x_1_10 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_CS_2147757484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.CS!MTB"
        threat_id = "2147757484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 0d e4 8b 7d 9c 30 14 38 83 f9 [0-48] 33 c9 [0-32] 41 40 3b c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_KB_2147758576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.KB"
        threat_id = "2147758576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "9d/L!St6j7W(A*4b" ascii //weight: 2
        $x_2_2 = "Dw4^i*M38o~CG)" ascii //weight: 2
        $x_2_3 = "jK!2(4XaYw9*@7Df" ascii //weight: 2
        $x_1_4 = "8f3c03efcf35549344924d397bad81f0.Resources.resources" ascii //weight: 1
        $x_1_5 = "$45eb8ae2-7e88-43c3-83ea-3f00c927d88c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_DE_2147760926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.DE!MTB"
        threat_id = "2147760926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 ff 88 45 ?? 8a 45 ?? 34 ?? 88 45 ?? 03 11 [0-48] 8a 45 ?? 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_EA_2147761569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.EA!MTB"
        threat_id = "2147761569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HkHKlNtiqIuaiQ5F9q4HlgEVVUG9zg3Yx190" wide //weight: 1
        $x_1_2 = "cp8lmkyTq7pOtUuyyQkhUy9bnMPpbciY14" wide //weight: 1
        $x_1_3 = "Vmk5zQ4BYZLmzRmbnK1xF9jq126" wide //weight: 1
        $x_1_4 = "pQ31KqI4L4WasjrdQHTgHtRIyzTYZLVhcaWIC180" wide //weight: 1
        $x_1_5 = "kfcVVDMcmMaHZI9K9tlYjJztsBljJG56" wide //weight: 1
        $x_1_6 = "Fkl0RZZrDAAF9OXOf8ovoeKMOtEhSQ4I171" wide //weight: 1
        $x_1_7 = "ZU0MfBLgKyLWYpVzV218" wide //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_GV_2147761900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.GV!MTB"
        threat_id = "2147761900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 81 c9 ?? ?? ?? ?? 8b 34 0a 89 34 08 81 34 08 ?? ?? ?? ?? 83 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_SM_2147770351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.SM!MTB"
        threat_id = "2147770351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 34 24 4a 5b 7d 82 81 3c 24 89 2a ac 60 81 3c 24 af 1f b3 ac 8f 04 08 81 3c 24 1d 1d 44 49 81 7d 00 40 00 b2 8c 01 d9 81 3c 24 33 4b 73 1c 81 7d 00 b2 3b da 19 81 f9 30 73 00 00 75 a3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_RVA_2147782036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.RVA!MTB"
        threat_id = "2147782036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 3d 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 43 00 68 00 72 00 22 00 20 00 2c 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 3d 20 43 41 4c 4c 20 28 20 22 43 68 72 22 20 2c 20 42 49 54 58 4f 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 76 00 78 00 6f 00 73 00 78 00 71 00 2e 00 2f 00 33 00 79 00 71 00 71 00 22 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 29 00 20 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-20] 20 28 20 22 76 78 6f 73 78 71 2e 2f 33 79 71 71 22 20 29 20 2c 20 00 20 28 20 22 [0-20] 22 20 29 20 2c}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 29 00 20 00 26 00 20 00 24 00 [0-20] 20 00 26 00 20 00 01 20 00 28 00 20 00 22 00 40 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-20] 20 28 20 22 [0-20] 22 20 29 20 26 20 24 [0-20] 20 26 20 01 20 28 20 22 40 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FormBook_AMP_2147782993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AMP!MTB"
        threat_id = "2147782993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kernel32::CreateFile(t'" ascii //weight: 1
        $x_1_2 = "kernel32::VirtualProtect(i r8, i " ascii //weight: 1
        $x_1_3 = "kernel32::ReadFile(i r10, i r8, i " ascii //weight: 1
        $x_1_4 = "kernel32::GetCurrentProcess()i.r5" ascii //weight: 1
        $x_1_5 = "Qkkbal" ascii //weight: 1
        $x_1_6 = "lOwqlOw" ascii //weight: 1
        $x_1_7 = ".DEFAULT\\Control Panel\\International" ascii //weight: 1
        $x_1_8 = "Control Panel\\Desktop\\ResourceLocale" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_10 = "Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 1
        $x_1_11 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AMP_2147782993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AMP!MTB"
        threat_id = "2147782993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Alloc" ascii //weight: 1
        $x_1_2 = "kernel32::CreateFile(t'" ascii //weight: 1
        $x_1_3 = "i 0x80000000, i 0, p 0, i 3, i 0, i 0)i.r10" ascii //weight: 1
        $x_1_4 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 3a 00 3a 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 28 00 69 00 20 00 72 00 38 00 2c 00 20 00 69 00 20 00 [0-5] 2c 00 20 00 69 00 20 00 30 00 78 00 34 00 30 00 2c 00 20 00 70 00 30 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6b 65 72 6e 65 6c 33 32 3a 3a 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 28 69 20 72 38 2c 20 69 20 [0-5] 2c 20 69 20 30 78 34 30 2c 20 70 30 29}  //weight: 1, accuracy: Low
        $x_1_6 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 3a 00 3a 00 52 00 65 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 69 00 20 00 72 00 31 00 30 00 2c 00 20 00 69 00 20 00 72 00 38 00 2c 00 20 00 69 00 20 00 [0-5] 2c 00 20 00 74 00 2e 00 2c 00 20 00 69 00 20 00 30 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6b 65 72 6e 65 6c 33 32 3a 3a 52 65 61 64 46 69 6c 65 28 69 20 72 31 30 2c 20 69 20 72 38 2c 20 69 20 [0-5] 2c 20 74 2e 2c 20 69 20 30 29}  //weight: 1, accuracy: Low
        $x_1_8 = "kernel32::EnumDateFormatsA(i r8, i 0, i0).i r5" ascii //weight: 1
        $x_1_9 = ".DEFAULT\\Control Panel\\International" ascii //weight: 1
        $x_1_10 = "Control Panel\\Desktop\\ResourceLocale" ascii //weight: 1
        $x_1_11 = "[Rename]" ascii //weight: 1
        $x_1_12 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_13 = "Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 1
        $x_1_14 = "Qkkbal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Trojan_Win32_FormBook_PRF_2147786870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.PRF!MTB"
        threat_id = "2147786870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 18 40 83 ee 01 75 f8 33 c9 8a 81 08 ?? 42 00 c0 c8 03 32 83 70 e4 41 00 88 81 08 00 42 00 8d 43 01 6a 0d 99 5e f7 fe 41 b8 ?? ?? 00 00 8b da 3b c8 72 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_RVB_2147794757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.RVB!MTB"
        threat_id = "2147794757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 4a 00 51 00 5c 00 4d 00 73 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 01 20 00 28 00 20 00 22 00 75 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-20] 20 28 20 22 4a 51 5c 4d 73 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 01 20 28 20 22 75 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 61 6c 6c 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {57 00 48 00 49 00 4c 00 45 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 46 00 54 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 3e 00 20 00 30 00}  //weight: 1, accuracy: Low
        $x_1_10 = {57 48 49 4c 45 20 41 53 43 20 28 20 53 54 52 49 4e 47 4c 45 46 54 20 28 20 24 [0-20] 20 2c 20 31 20 29 20 29 3e 20 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_FormBook_RVC_2147795374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.RVC!MTB"
        threat_id = "2147795374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 30 00 32 00 20 00 31 00 32 00 35 00 20 00 31 00 32 00 30 00 20 00 31 00 30 00 35 00 20 00 39 00 35 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 01 20 00 28 00 20 00 22 00 39 00 37 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 43 41 4c 4c 20 28 20 22 44 6c 6c 53 74 72 75 63 74 43 72 65 61 74 65 22 20 2c 20 [0-20] 20 28 20 22 31 30 32 20 31 32 35 20 31 32 30 20 31 30 35 20 39 35 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 01 20 28 20 22 39 37 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 43 00 68 00 72 00 22 00 20 00 2c 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 4e 00 75 00 6d 00 62 00 65 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 5b 00 20 00 24 00 [0-20] 20 00 5d 00 20 00 29 00 20 00 2b 00 20 00 2d 00 34 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 43 41 4c 4c 20 28 20 22 43 68 72 22 20 2c 20 43 41 4c 4c 20 28 20 22 4e 75 6d 62 65 72 22 20 2c 20 24 [0-20] 20 5b 20 24 [0-20] 20 5d 20 29 20 2b 20 2d 34 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 67 00 53 00 70 00 6c 00 69 00 74 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 22 00 27 00 20 00 26 00 20 00 27 00 20 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 41 4c 4c 20 28 20 22 53 74 72 69 6e 67 53 70 6c 69 74 22 20 2c 20 24 [0-20] 20 2c 20 22 27 20 26 20 27 20 22 20 2c 20 32 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FormBook_NE_2147798992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NE!MTB"
        threat_id = "2147798992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 f1 cb 00 00 00 88 4d db 0f b6 75 db c1 fe 05 0f b6 7d db c1 e7 03 89 f3 09 fb 88 5d db 0f b6 75 db 89 c1 29 f1 88 4d db 0f b6 75 db 89 f1 83 f1 15 88 4d db 0f b6 75 db 89 f1 83 f1 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_RVD_2147807231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.RVD!MTB"
        threat_id = "2147807231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-20] 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4d 4f 44 20 28 20 24 [0-20] 20 2b 20 31 33 20 2c 20 32 35 36 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 55 00 [0-16] 30 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 01 20 00 28 00 20 00 22 00 6a 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-20] 20 28 20 22 55 [0-16] 30 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 01 20 28 20 22 6a 22 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FormBook_RVD_2147807231_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.RVD!MTB"
        threat_id = "2147807231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 00 20 00 22 00 43 00 68 00 72 00 22 00 20 00 2c 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 42 00 69 00 74 00 58 00 4f 00 52 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {28 20 22 43 68 72 22 20 2c 20 43 41 4c 4c 20 28 20 22 42 69 74 58 4f 52 22 20 2c 20 24 [0-20] 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {28 00 20 00 22 00 4d 00 6f 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {28 20 22 4d 6f 64 22 20 2c 20 24 [0-20] 20 2b 20 31 33 20 2c 20 32 35 36 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 55 00 3d 00 25 00 3b 00 30 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 01 20 00 28 00 20 00 22 00 6a 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-20] 20 28 20 22 55 3d 25 3b 30 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 01 20 28 20 22 6a 22 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FormBook_EM_2147813927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.EM!MTB"
        threat_id = "2147813927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 81 a8 00 00 25 ce 86 00 00 40 59 3d 3a b3 00 00 74 06 49 b9 66 8b 00 00 41 81 ea b2 b1 00 00 81 e9 08 82 01 00 f7 d2 bb 7c 77 00 00 81 e2 45 85 00 00 81 e1 a1 f6 00 00 b8 a0 86 01 00 43 81 e9 ed 64 01 00 40 5b f7 d0 59 48 81 f1 bc 13 01 00 ba 7c bf 00 00 81 e3 75 66 01 00 c2 dd 19}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_GA_2147813935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.GA!MTB"
        threat_id = "2147813935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 61 12 00 00 74 ?? 4b c2 82 18 81 f2 bc 13 01 00 48 49 25 d7 78 01 00 f7 d2 81 eb e2 4a 01 00 c2 dd 61 35 4a fe 00 00 81 e2 09 f2 00 00 81 c1 bc 5b 01 00 81 c3 3f 74 01 00 81 e2 3a fb 00 00 81 f9 86 d9 00 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {25 e8 eb 00 00 81 c1 ee d4 00 00 42 81 f1 92 63 00 00 81 f3 dd 61 01 00 81 f1 3b 23 00 00 f7 d2 c2 90 83 81 c1 90 83 01 00 81 f2 82 18 00 00 b9 2e 71 01 00 4a 05 a2 66 00 00 49 81 fb c2 b4 00 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_EC_2147814123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.EC!MTB"
        threat_id = "2147814123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "nViable Solutionp.pcr" ascii //weight: 3
        $x_3_2 = "Don HO" ascii //weight: 3
        $x_3_3 = "WA_QMSIM" ascii //weight: 3
        $x_3_4 = "SetLayeredWindowAttributes" ascii //weight: 3
        $x_3_5 = "psRunning" ascii //weight: 3
        $x_3_6 = "TaskbarCreated" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_DM_2147814559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.DM!MTB"
        threat_id = "2147814559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5b 81 f9 1a 65 00 00 74 10 59 40 2d 1e 26 01 00 81 c2 2e 71 01 00 49 40 58 58 b8 41 0c 00 00 81 ea c7 2d 01 00 f7 d0 c2 56 88 59 81 c2 b3 69 00 00 81 e3 a2 66 00 00 bb f3 05 01 00 f7 d3 3d 6b 04 01 00 74 14}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_MC_2147814638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.MC!MTB"
        threat_id = "2147814638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 e3 e8 eb 00 00 81 e1 8d 32 00 00 f7 d3 c2 51 57 5b 81 c1 c7 75 01 00 49 81 c3 f3 bd 00 00 b8 61 12 00 00 81 f3 97 94 00 00 81 fa 81 a8 00 00 74 0f 41 f7 d1 c2 2e 71 b9 67 43 00 00 48 c2 1f de 81 f2 9d 35 00 00 4b bb 05 31 00 00 c2 70 35}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_ER_2147820476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.ER!MTB"
        threat_id = "2147820476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 f0 31 c9 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {89 45 e8 c7 04 24 80 74 d2 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_ABFJ_2147837445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.ABFJ!MTB"
        threat_id = "2147837445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 55 ff 0f b6 4d ff 2b 4d f0 88 4d ff 0f b6 55 ff c1 fa ?? 0f b6 45 ff c1 e0 ?? 0b d0 88 55 ff 0f b6 4d ff f7 d1 88 4d ff 0f b6 55 ff 83 ea ?? 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 8b 4d e8 03 4d f0 8a 55 ff 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AKR_2147837713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AKR!MTB"
        threat_id = "2147837713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 3b 04 04 34 8a 04 74 34 be 04 30 34 9b 2c 67 34 3d 88 04 3b 47 3b 7d fc 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AESL_2147837829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AESL!MTB"
        threat_id = "2147837829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 37 34 4e 2c 74 34 55 88 04 37 46 3b f3 72}  //weight: 2, accuracy: High
        $x_1_2 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_MBO_2147837951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.MBO!MTB"
        threat_id = "2147837951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 83 f2 03 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 83 ea 44 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 f0 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15 ?? ?? ?? ?? 89 45 f8 6a 00 8d 45 d8 50 8b 4d f0 51 8b 55 f8 52 8b 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AEL_2147838075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AEL!MTB"
        threat_id = "2147838075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d 10 8a 04 39 04 22 34 6d 2c 61 34 cf fe c8 34 15 2c 36 88 04 39 47 3b fb}  //weight: 2, accuracy: High
        $x_1_2 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_MBT_2147838097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.MBT!MTB"
        threat_id = "2147838097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 37 04 22 34 3b fe c8 34 ee 04 74 34 bf 04 63 88 04 37 46 3b f3 72 e7}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 30 00 00 8b d8 53 6a 00 ff d7 8b 55 10 6a 00 8d 4d fc 51 53 8b f8 57 52 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_MBAM_2147838708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.MBAM!MTB"
        threat_id = "2147838708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 99 b9 0c 00 00 00 f7 f9 8b 45 b8 0f b6 0c 10 8b 55 f0 03 55 f4 0f b6 02 33 c1 8b 4d f0 03 4d f4 88 01}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 8b 4d ec 51 e8 cb 8f 00 00 83 c4 0c 6a 40 68 00 30 00 00 8b 55 e8 52 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_EB_2147839733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.EB!MTB"
        threat_id = "2147839733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {fe c8 fe c0 fe c0 fe c0 34 6b fe c0 2c 1c fe c0 fe c0 fe c0 34 7f 04 71 fe c0 2c 57}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_EB_2147839733_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.EB!MTB"
        threat_id = "2147839733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {88 37 80 e2 d4 88 d4 20 c4 30 d0 08 e0 88 47 01 0f b6 47 02 88 c4 89 c2 80 f4 d5 80 e2 90 20 c4 f6 d0 24 45 08 c2 80 f2 90}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFM_2147841505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFM!MTB"
        threat_id = "2147841505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 03 c1 89 44 24 10 8b c1 99 6a 0c 5e f7 fe 8b 74 24 10 8a 82 ?? ?? ?? ?? 30 06 41 3b cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFM_2147841505_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFM!MTB"
        threat_id = "2147841505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f6 89 f6 89 f6 89 f6 89 f6 8b 4d fc 03 cf 89 f6 89 f6 8a 10 89 f6 89 f6 89 f6 89 f6 32 55 fa 88 11 89 f6 8a 55 fb 30 11 89 f6 89 f6 89 f6 89 f6 47 40 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AROO_2147841580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AROO!MTB"
        threat_id = "2147841580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f0 f7 e1 d1 ea 83 e2 ?? 8d 04 52 f7 d8 8a 84 06 ?? ?? ?? ?? 30 04 33 46 39 f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_GFE_2147841694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.GFE!MTB"
        threat_id = "2147841694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 13 34 65 2c 03 2c 81 04 68 34 b9 04 25 34 56 2c 79 2c bb 34 b5 88 84 0d ?? ?? ?? ?? 83 c1 ?? eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_GFG_2147841706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.GFG!MTB"
        threat_id = "2147841706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {34 5c 04 7d fe c0 04 01 04 ca 34 72 fe c0 04 82 04 7f 34 7f 2c 92 34 62 2c 08 fe c0 04 4f fe c0 88 84 0d ?? ?? ?? ?? 83 c1 ?? eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFN_2147842160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFN!MTB"
        threat_id = "2147842160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 c0 89 45 bc 8b 45 dc b9 ?? ?? ?? ?? 99 f7 f9 8b 45 bc 0f b6 34 10 8b 45 cc 8b 4d dc 0f b6 14 08 31 f2 88 14 08 8b 45 dc 83 c0 01 89 45 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_ARN_2147842161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.ARN!MTB"
        threat_id = "2147842161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 99 b9 ?? ?? ?? ?? f7 f9 8b 45 e4 0f b6 0c 10 8b 55 dc 03 55 f8 0f b6 02 33 c1 8b 4d dc 03 4d f8 88 01 8b 55 f8 83 c2 01 89 55 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_ATA_2147843571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.ATA!MTB"
        threat_id = "2147843571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 53 50 56 ff 15 ?? ?? ?? ?? 8b 4d 10 8a 04 39 2c 2d 34 40 04 0c 34 b8 fe c8 88 04 39 47 3b fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_GB_2147843580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.GB!MTB"
        threat_id = "2147843580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 07 8e 69 8d ?? ?? ?? 01 0d 16 13 05 2b 1a 00 09 11 05 07 11 05 91 08 11 05 08 8e 69 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_SISN_2147845368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.SISN!MTB"
        threat_id = "2147845368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 55 f8 88 55 ff 0f b6 45 ff c1 f8 05 0f b6 4d ff c1 e1 03 0b c1 88 45 ff 0f b6 55 ff 03 55 f8 88 55 ff 0f b6 45 ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff f7 da 88 55 ff 0f b6 45 ff 2b 45 f8 88 45 ff 0f b6 4d ff 81}  //weight: 1, accuracy: High
        $x_1_3 = {81 e9 92 00 00 00 88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 83 e9 5e 88 4d ff 0f b6 55 ff f7 da 88 55 ff}  //weight: 1, accuracy: High
        $x_1_4 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 83 e9 5e}  //weight: 1, accuracy: High
        $x_1_5 = {0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff f7 d2 88 55 ff 0f b6 45 ff f7 d8}  //weight: 1, accuracy: High
        $x_1_6 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff}  //weight: 1, accuracy: High
        $x_1_7 = {88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff f7 da 88 55 ff 0f b6 45 ff 2b 45 f8 88 45 ff 0f b6 4d ff f7 d9}  //weight: 1, accuracy: High
        $x_1_8 = {0b ca 88 4d ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff f7 da}  //weight: 1, accuracy: High
        $x_1_9 = {88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 2b 55 f8 88 55 ff 0f b6 45 ff d1 f8}  //weight: 1, accuracy: High
        $x_1_10 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff c1 f8 06 0f b6 4d ff c1 e1 02}  //weight: 1, accuracy: High
        $x_1_11 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff c1 f8 02 0f b6 4d ff c1 e1 06 0b c1 88 45 ff}  //weight: 1, accuracy: High
        $x_1_12 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff}  //weight: 1, accuracy: High
        $x_1_13 = {68 50 00 10 85 c0 59 a3 14 44 00 10 75 04 33 c0 eb 66 83 20 00 a1 14 44 00 10 68 04 60 00 10 68 00 60 00 10 a3 10 44 00 10 e8 ad 2e 00 00 ff 05 08 44 00 10 59 59 eb 3d 85 c0 75 39 a1 14 44 00 10 85 c0 74 30 8b 0d 10 44 00 10 56 8d 71 fc 3b f0 72 12 8b 0e 85 c9 74 07 ff d1 a1 14 44 00 10 83 ee 04 eb ea 50 ff 15 70 50 00 10 83 25 14 44 00 10 00 59 5e 6a 01 58 c2 0c 00 55 8b ec 53 8b 5d 08 56 8b 75 0c 57 8b 7d 10 85 f6 75 09 83 3d 08 44 00 10 00 eb 26 83 fe 01 74 05 83 fe 02 75 22 a1 18 44 00 10 85 c0 74 09 57 56 53 ff d0 85}  //weight: 1, accuracy: High
        $x_1_14 = {33 c0 eb 66 83 20 00 a1 bc 74 00 10 68 a8 74 00 10 68 a4 74 00 10 a3 c0 74 00 10 e8 7a 01 00 00 ff 05 b4 74 00 10 59 59 eb 3d 85 c0 75 39 a1 bc 74 00 10 85 c0 74 30 8b 0d c0 74 00 10 56 8d 71 fc 3b f0 72 12 8b 0e 85 c9 74 07 ff d1 a1 bc 74 00 10 83 ee 04 eb ea 50 ff 15 20 5a 00 10 83 25 bc 74 00 10 00 59 5e 6a 01 58 c2 0c 00 55}  //weight: 1, accuracy: High
        $x_1_15 = {33 58 00 00 77 64 6c 69 6c 63 6c 76 2e 64 6c 6c 00 00 00 00 00 70 2c 00 00 35 58 00 00 01 00 63 63}  //weight: 1, accuracy: High
        $x_1_16 = {32 0d 42 17 c2 ec 67 66 46 78 01 06 4a bd 81 df d9 b7 41 b9 78 95 35 f6 13 3d 1f f7 7d e6 e7 01 8d e3 1e}  //weight: 1, accuracy: High
        $x_1_17 = {33 45 f8 88 45 ff 0f b6 45 ff d1 f8 0f b6 4d ff c1 e1 07 0b c1 88 45 ff}  //weight: 1, accuracy: High
        $x_1_18 = {4d 0c 6b c9 30 01 c8 8b 4d f4 8b 49 60 0f b7 55 0c 83 c2 01 6b d2 30 01 d1 8b 55 f4 8b 52 5c 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FormBook_AFB_2147849823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFB!MTB"
        threat_id = "2147849823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff d6 68 ?? ?? ?? ?? 53 a3 08 c9 43 00 ff d7 50 ff d6 68 ?? ?? ?? ?? 53 a3 0c c9 43 00 ff d7 50 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFB_2147849823_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFB!MTB"
        threat_id = "2147849823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 33 c9 b8 ?? ?? ?? ?? f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8d 04 80 03 c0 03 c0 8b d1 2b d0 8a 04 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFB_2147849823_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFB!MTB"
        threat_id = "2147849823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 47 54 46 8a 40 03 30 44 1e ff 0f b6 4c 1e ff 8b 47 54 8a 50 02 32 d1 88 54 1e ff 8b 47 54 8a 48 01 32 ca 88 4c 1e ff 8b 47 54 8a 00 32 c1 88 44 1e ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFK_2147852185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFK!MTB"
        threat_id = "2147852185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ca 83 e1 0f 42 8a 0c 19 88 4c 02 ff 3b d7 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFK_2147852185_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFK!MTB"
        threat_id = "2147852185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 5e 02 88 4e 02 88 5c 02 02 0f b6 4e 02 8b 55 0c 02 cb 0f b6 c9 0f b6 4c 01 02 32 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFK_2147852185_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFK!MTB"
        threat_id = "2147852185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 06 5f c6 44 24 0c 79 c6 44 24 03 65 c6 44 24 04 6c c6 44 24 08 6f c6 44 24 0e 63 c6 04 24 48 c6 44 24 0a 69 c6 44 24 01 53 c6 44 24 0f 6f c6 44 24 07 4e c6 44 24 0d 49 c6 44 24 02 68 c6 44 24 0b 66 c6 44 24 11 41 c6 44 24 05 6c c6 44 24 09 74 c6 44 24 10 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFK_2147852185_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFK!MTB"
        threat_id = "2147852185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 85 14 ff ff ff 7b 00 30 00 c7 85 18 ff ff ff 30 00 30 00 c7 85 1c ff ff ff 30 00 30 00 c7 85 20 ff ff ff 31 00 30 00 c7 85 24 ff ff ff 43 00 2d 00 c7 85 28 ff ff ff 30 00 30 00 c7 85 2c ff ff ff 30 00 30 00 c7 85 30 ff ff ff 2d 00 30 00 c7 85 34 ff ff ff 30 00 30 00 c7 85 38 ff ff ff 30 00 2d 00 c7 85 3c ff ff ff 43 00 30 00 c7 85 40 ff ff ff 30 00 30 00 c7 85 44 ff ff ff 2d 00 30 00 c7 85 48 ff ff ff 30 00 30 00 c7 85 4c ff ff ff 30 00 30 00 c7 85 50 ff ff ff 30 00 30 00 c7 85 54 ff ff ff 30 00 30 00 c7 85 58 ff ff ff 30 00 34 00 c7 85 5c ff ff ff 36 00 7d 00 c7 45 d0 01 00 00 00 89 7d d4 c7 45 e4 00 01 00 00 89 45 e0 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_HNS_2147889119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.HNS!MTB"
        threat_id = "2147889119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "unpacking data: %d%%" wide //weight: 1
        $x_1_2 = "Error writing temporary file. Make sure your temp folder is valid" wide //weight: 1
        $x_3_3 = {74 00 72 00 69 00 73 00 61 00 63 00 63 00 68 00 61 00 72 00 69 00 64 00 65 00 00 00 ?? ?? ?? ?? 01 00 46}  //weight: 3, accuracy: Low
        $x_3_4 = {72 00 69 00 67 00 68 00 74 00 00 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 64 00 69 00 73 00 70 00 75 00 74 00 61 00 74 00 69 00 76 00 65 00 6c 00 79 00 00 00 ?? ?? ?? ?? 01 00 50}  //weight: 3, accuracy: Low
        $x_6_5 = {72 00 69 00 67 00 68 00 74 00 00 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 74 00 72 00 69 00 73 00 61 00 63 00 63 00 68 00 61 00 72 00 69 00 64 00 65 00 00 00 ?? ?? ?? ?? 01 00 4c}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_AMF_2147893058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AMF!MTB"
        threat_id = "2147893058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe c0 32 c1 c0 c0 02 2a c1 c0 c0 03 04 56 f6 d0 2c 19 34 18 f6 d8 d0 c8 04 0a f6 d0 02 c1 d0 c0 2a c1 34 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_MBKC_2147893901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.MBKC!MTB"
        threat_id = "2147893901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 41 01 f7 ef 8a 86 ?? ?? ?? ?? c0 c0 05 32 81 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 89 d0 c1 e8 1f c1 fa 02 01 c2 8d 04 52 8d 04 82 f7 d8 01 c1 41 46 75 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_MBKE_2147893902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.MBKE!MTB"
        threat_id = "2147893902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 49 8b 55 f8 8a 82 ?? ?? ?? ?? 88 45 ff 8b 4d e4 03 4d f4 8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2 8b 4d f8 88 81 ?? ?? ?? ?? 8b 45 f4 83 c0 01 99 b9 ?? ?? ?? ?? f7 f9 89 55 f4 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_QE_2147896082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.QE!MTB"
        threat_id = "2147896082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "uncanny.bat" ascii //weight: 3
        $x_3_2 = "zcnouvtpdrdm" ascii //weight: 3
        $x_3_3 = "tmp\\maauatqgcy.dll" ascii //weight: 3
        $x_3_4 = "opc_package_write" ascii //weight: 3
        $x_3_5 = "FmtIdToPropStgName" ascii //weight: 3
        $x_3_6 = "UtGetDvtd16Info" ascii //weight: 3
        $x_3_7 = "vxfvacf" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_NA_2147907457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NA!MTB"
        threat_id = "2147907457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "renowner" ascii //weight: 3
        $x_3_2 = "phagocytosed" ascii //weight: 3
        $x_1_3 = "EXECUTE" ascii //weight: 1
        $x_1_4 = "TEMPDIR" ascii //weight: 1
        $x_1_5 = "REGWRITE" ascii //weight: 1
        $x_1_6 = "D3134VSXTQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_NB_2147908385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NB!MTB"
        threat_id = "2147908385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "&= \"leOpen(@Te\"" ascii //weight: 3
        $x_3_2 = "&= \"mpDir & \"" ascii //weight: 3
        $x_1_3 = "FILEINSTALL" ascii //weight: 1
        $x_1_4 = "@TEMPDIR &" ascii //weight: 1
        $x_1_5 = "llCall(Bi" ascii //weight: 1
        $x_1_6 = "&= \"uctCreate(BinaryToStr\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_NG_2147909863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NG!MTB"
        threat_id = "2147909863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EXECUTE ( \"@tempdir\" ) &" ascii //weight: 2
        $x_2_2 = "= EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" &" ascii //weight: 2
        $x_2_3 = "= EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"R\" & \"e\" & \"pl\" & \"ac\" &" ascii //weight: 2
        $x_1_4 = "t\" & \"e\" & \"m\" & \"p\" & \"d\" & \"i\" &" ascii //weight: 1
        $x_1_5 = "REGWRITE (" ascii //weight: 1
        $x_1_6 = "REGDELETE (" ascii //weight: 1
        $x_1_7 = "FILEINSTALL (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_AFR_2147910320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFR!MTB"
        threat_id = "2147910320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 89 45 a8 33 ff 8b 0d ?? ?? ?? ?? 0f af cb b8 7f e0 07 7e f7 e9 c1 fa 05 8d 73 01 8b c2 8b ce 0f af 0d ?? ?? ?? ?? c1 e8 1f 03 c2 89 45 ec b8 7f e0 07 7e f7 e9 c1 fa 05 8b ca c1 e9 1f 03 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_NH_2147910553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NH!MTB"
        threat_id = "2147910553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = "&= EXECUTE ( \"C\" & \"h\" & \"r(B\" & \"i\" & \"t\" & \"X\" & \"O\" & \"R(" ascii //weight: 2
        $x_2_4 = "= EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" &" ascii //weight: 2
        $x_2_5 = "= EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"R\" & \"e\" & \"p\" & \"l\" &" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FormBook_NH_2147910553_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NH!MTB"
        threat_id = "2147910553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 40 00 74 00 65 00 6d 00 70 00 64 00 69 00 72 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 45 58 45 43 55 54 45 20 28 20 22 40 74 65 6d 70 64 69 72 22 20 29 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = "\"048B4C24088B008B093BC8760483C8FFC31BC0F7D8C38B\"" ascii //weight: 2
        $x_2_4 = "FILEREAD ( FILEOPEN ( @TEMPDIR &" ascii //weight: 2
        $x_2_5 = "&= CHR ( BITXOR ( ASC ( STRINGMID (" ascii //weight: 2
        $x_1_6 = "= 1 TO STRINGLEN" ascii //weight: 1
        $x_1_7 = "REGWRITE (" ascii //weight: 1
        $x_1_8 = "FILEDELETE (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NF_2147912072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NF!MTB"
        threat_id = "2147912072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 52 01 66 89 06 8a ?? 8d 76 02 84 c0 75 ef 5e}  //weight: 3, accuracy: Low
        $x_3_2 = {33 c0 38 01 74 0d 8d 49 00 80 7c 08 01 ?? 8d 40 01 75 f6 33 c9 66}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_PNAA_2147913867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.PNAA!MTB"
        threat_id = "2147913867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&= EXECUTE ( \"Chr(Asc(StringMid" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"Stri\" & \"ngLe\" & \"ft" ascii //weight: 1
        $x_1_3 = "@TEMPDIR &" ascii //weight: 1
        $x_1_4 = "EXECUTE ( \"Fil\" & \"eRe\" & \"ad(Fil\" & \"eOp\" & \"en(@Tem\" & \"pDir & \"" ascii //weight: 1
        $x_1_5 = "EXECUTE ( \"DllC\" & \"all" ascii //weight: 1
        $x_1_6 = "EXECUTE ( \"DllStruc\" & \"tCreate" ascii //weight: 1
        $x_1_7 = "EXECUTE ( \"DllS\" & \"tru\" & \"ctSe\" & \"tDat\" & \"a" ascii //weight: 1
        $x_1_8 = "EXECUTE ( \"Dl\" & \"lCall\" & \"Add\" & \"ress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_NP_2147915266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NP!MTB"
        threat_id = "2147915266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "&= EXECUTE ( \"Chr(Asc(StringMid(" ascii //weight: 2
        $x_2_4 = "= EXECUTE ( \"DllStruc\" & \"tCreate(" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_Z_2147916944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.Z!MTB"
        threat_id = "2147916944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 30 50 4f 53 54 74 09 40}  //weight: 1, accuracy: High
        $x_1_2 = {04 83 c4 0c 83 06 07 5b 5f 5e 8b e5 5d c3 8b 17 03 55 0c 6a 01 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_Z_2147916944_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.Z!MTB"
        threat_id = "2147916944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0a 4e 0f b6 08 8d 44 08 01 75 f6 8d 70 01 0f b6 00 8d 55}  //weight: 1, accuracy: High
        $x_1_2 = {1a d2 80 e2 af 80 c2 7e eb 2a 80 fa 2f 75 11 8a d0 80 e2 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_Z_2147916944_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.Z!MTB"
        threat_id = "2147916944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c8 0f 31 2b c1 89 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {3c 24 0f 84 76 ff ff ff 3c 25 74 94}  //weight: 1, accuracy: High
        $x_1_3 = {3b 4f 14 73 95 85 c9 74 91}  //weight: 1, accuracy: High
        $x_1_4 = {3c 69 75 44 8b 7d 18 8b 0f}  //weight: 1, accuracy: High
        $x_1_5 = {5d c3 8d 50 7c 80 fa 07}  //weight: 1, accuracy: High
        $x_1_6 = {0f be 5c 0e 01 0f b6 54 0e 02 83 e3 0f c1 ea 06}  //weight: 1, accuracy: High
        $x_1_7 = {57 89 45 fc 89 45 f4 89 45 f8}  //weight: 1, accuracy: High
        $x_1_8 = {66 89 0c 02 5b 8b e5 5d}  //weight: 1, accuracy: High
        $x_1_9 = {3c 54 74 04 3c 74 75 f4}  //weight: 1, accuracy: High
        $x_1_10 = {56 68 03 01 00 00 8d 85 95 fe ff ff 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_FormBook_AFO_2147919711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AFO!MTB"
        threat_id = "2147919711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 59 8d 85 7c ea ff ff 50 8d 85 5c eb ff ff 50 8d 85 a0 eb ff ff 50 8d 85 54 eb ff ff 50 8d 85 4c fc ff ff 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 00 8d 85 74 fd ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 74 3b a1 ?? ?? ?? ?? 0f af 45 c8 03 45 cc a3 ?? ?? ?? ?? 8b 45 98 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_NMA_2147923482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NMA!MTB"
        threat_id = "2147923482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 4f 43 41 4c 20 24 [0-47] 20 3d 20 4d 4f 44 20 28 20 24 [0-47] 20 2c 20 32 35 36 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 4f 00 52 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 4f 52 20 24 [0-47] 20 3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e}  //weight: 1, accuracy: Low
        $x_1_7 = "&= CHR ( BITXOR ( ASC ( CHR" ascii //weight: 1
        $x_1_8 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 41 00 73 00 63 00 28 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00}  //weight: 1, accuracy: Low
        $x_1_9 = {4c 4f 43 41 4c 20 24 [0-47] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 41 73 63 28 53 74 72 69 6e 67 4d 69 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NOB_2147924092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NOB!MTB"
        threat_id = "2147924092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-47] 20 2c 20 24 [0-47] 20 2c 20 31 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 4f 00 52 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 4f 52 20 24 [0-47] 20 3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e}  //weight: 1, accuracy: Low
        $x_1_7 = "RETURN STRINGREVERSE" ascii //weight: 1
        $x_1_8 = "m9554jjjjhj4m95h4ojn" ascii //weight: 1
        $x_1_9 = "h9554jjjjhj8o95h4" ascii //weight: 1
        $x_1_10 = "944no4hjjjjijo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NOE_2147930042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NOE!MTB"
        threat_id = "2147930042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 48 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-31] 20 2c 20 24 [0-31] 20 2c 20 31 20 29 20 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_5 = {49 00 46 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 3d 00 20 00 30 00 20 00 54 00 48 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_6 = {49 46 20 4d 4f 44 20 28 20 24 [0-31] 20 2c 20 32 20 29 20 3d 20 30 20 54 48 45 4e}  //weight: 1, accuracy: Low
        $x_1_7 = "&= EXECUTE ( \"C\" & \"hr(As\" & \"c(Strin\" & \"gMid(" ascii //weight: 1
        $x_1_8 = "PolzogfGfrii" ascii //weight: 1
        $x_1_9 = "=gfrQohji}Jxii" ascii //weight: 1
        $x_1_10 = "PolzogfLlk_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NOG_2147930457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NOG!MTB"
        threat_id = "2147930457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "& \"(@TempDir &" ascii //weight: 2
        $x_1_2 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 [0-31] 20 00 28 00 20 00 22 00 4a 00 6e 00 72 00 6c 00 5a 00 6e 00 6b 00 6f 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-31] 20 3d 20 [0-31] 20 28 20 22 4a 6e 72 6c 5a 6e 6b 6f 22 20 2c 20 33 20 29}  //weight: 1, accuracy: Low
        $x_1_4 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 [0-31] 20 00 28 00 20 00 22 00 4a 00 6e 00 72 00 6c 00 57 00 79 00 6f 00 79 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-31] 20 3d 20 [0-31] 20 28 20 22 4a 6e 72 6c 57 79 6f 79 22 20 2c 20 33 20 29}  //weight: 1, accuracy: Low
        $x_1_6 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 [0-31] 20 00 28 00 20 00 22 00 46 00 6e 00 74 00 68 00 7a 00 e2 00 80 00 9a 00 56 00 70 00 7a 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-31] 20 3d 20 [0-31] 20 28 20 22 46 6e 74 68 7a e2 80 9a 56 70 7a 22 20 2c 20 33 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2d 00 20 00 4d 00 4f 00 44 00}  //weight: 1, accuracy: Low
        $x_1_9 = {26 3d 20 43 48 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-31] 20 2c 20 24 [0-31] 20 2c 20 31 20 29 20 29 20 2d 20 4d 4f 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NOH_2147930730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NOH!MTB"
        threat_id = "2147930730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 00 20 00 22 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 [0-31] 22 00 2c 00 20 00 31 00 38 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {26 20 22 28 40 54 65 6d 70 44 69 72 20 26 20 22 [0-31] 22 2c 20 31 38 29 22 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {46 00 4f 00 52 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 4f 52 20 24 [0-31] 20 3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-31] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 [0-31] 20 00 28 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-31] 20 3d 20 [0-31] 20 28 20 22}  //weight: 1, accuracy: Low
        $x_1_7 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 68 00 72 00 28 00 41 00 73 00 63 00 28 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 28 00 24 00 [0-31] 2c 00 20 00 24 00 [0-31] 2c 00 20 00 31 00 29 00 29 00 20 00 2d 00 20 00 4d 00 6f 00 64 00 28 00 24 00 [0-31] 20 00 2b 00 20 00 24 00 [0-31] 2c 00 20 00 32 00 35 00 36 00 29 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 68 72 28 41 73 63 28 53 74 72 69 6e 67 4d 69 64 28 24 [0-31] 2c 20 24 [0-31] 2c 20 31 29 29 20 2d 20 4d 6f 64 28 24 [0-31] 20 2b 20 24 [0-31] 2c 20 32 35 36 29 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_10 = "561840652" ascii //weight: 1
        $x_1_11 = "Snapshots" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NOK_2147931100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NOK!MTB"
        threat_id = "2147931100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-31] 20 00 26 00 20 00 22 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 [0-31] 22 00 2c 00 20 00 31 00 38 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 20 45 58 45 43 55 54 45 20 28 20 24 [0-31] 20 26 20 22 28 40 54 65 6d 70 44 69 72 20 26 20 22 [0-31] 22 2c 20 31 38 29 22 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {46 00 4f 00 52 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 [0-31] 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 4f 52 20 24 [0-31] 20 3d 20 31 20 54 4f 20 [0-31] 20 28 20 24 [0-31] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 [0-31] 20 00 28 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-31] 20 3d 20 [0-31] 20 28 20 22}  //weight: 1, accuracy: Low
        $x_1_7 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 [0-31] 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2d 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2b 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {26 3d 20 43 48 52 20 28 20 41 53 43 20 28 20 [0-31] 20 28 20 24 [0-31] 20 2c 20 24 [0-31] 20 2c 20 31 20 29 20 29 20 2d 20 4d 4f 44 20 28 20 24 [0-31] 20 2b 20 24 [0-31] 20 2c 20 32 35 36 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_10 = "68216381" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NOL_2147931101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NOL!MTB"
        threat_id = "2147931101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = "15111111111111100000000000000000005555" ascii //weight: 1
        $x_1_4 = {46 00 4f 00 52 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00 20 00 53 00 54 00 45 00 50 00 20 00 32 00}  //weight: 1, accuracy: Low
        $x_1_5 = {46 4f 52 20 24 [0-31] 20 3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-31] 20 29 20 53 54 45 50 20 32}  //weight: 1, accuracy: Low
        $x_1_6 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 41 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 28 00 53 00 74 00 72 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 4d 00 69 00 64 00 28 00 24 00 [0-31] 2c 00 20 00 24 00 [0-31] 2c 00 20 00 31 00 29 00 29 00 20 00 2d 00 20 00 28 00 24 00 [0-31] 20 00 2b 00 20 00 31 00 29 00 20 00 2f 00 20 00 32 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 68 22 20 26 20 22 72 28 41 73 22 20 26 20 22 63 28 53 74 72 69 6e 22 20 26 20 22 67 4d 69 64 28 24 [0-31] 2c 20 24 [0-31] 2c 20 31 29 29 20 2d 20 28 24 [0-31] 20 2b 20 31 29 20 2f 20 32 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 53 00 74 00 72 00 22 00 20 00 26 00 20 00 22 00 75 00 63 00 74 00 53 00 22 00 20 00 26 00 20 00 22 00 65 00 74 00 44 00 61 00 74 00 61 00 28 00 24 00 [0-31] 2c 00 20 00 31 00 2c 00 20 00 24 00 [0-31] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_9 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 22 20 26 20 22 6c 53 74 72 22 20 26 20 22 75 63 74 53 22 20 26 20 22 65 74 44 61 74 61 28 24 [0-31] 2c 20 31 2c 20 24 [0-31] 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_10 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 22 00 20 00 26 00 20 00 22 00 6c 00 6c 00 53 00 74 00 72 00 22 00 20 00 26 00 20 00 22 00 75 00 63 00 74 00 43 00 72 00 65 00 22 00 20 00 26 00 20 00 22 00 61 00 74 00 65 00 28 00}  //weight: 1, accuracy: Low
        $x_1_11 = {47 4c 4f 42 41 4c 20 24 [0-31] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 44 22 20 26 20 22 6c 6c 53 74 72 22 20 26 20 22 75 63 74 43 72 65 22 20 26 20 22 61 74 65 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NOQ_2147931296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NOQ!MTB"
        threat_id = "2147931296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-31] 20 00 26 00 20 00 22 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 [0-31] 22 00 2c 00 20 00 31 00 38 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 20 45 58 45 43 55 54 45 20 28 20 24 [0-31] 20 26 20 22 28 40 54 65 6d 70 44 69 72 20 26 20 22 [0-31] 22 2c 20 31 38 29 22 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {49 00 46 00 20 00 24 00 [0-31] 20 00 2b 00 20 00 24 00 [0-31] 20 00 2b 00 20 00 2d 00 31 00 3e 00 20 00 [0-31] 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00 20 00 54 00 48 00 45 00 4e 00 20 00 45 00 58 00 49 00 54 00 4c 00 4f 00 4f 00 50 00}  //weight: 1, accuracy: Low
        $x_1_4 = {49 46 20 24 [0-31] 20 2b 20 24 [0-31] 20 2b 20 2d 31 3e 20 [0-31] 20 28 20 24 [0-31] 20 29 20 54 48 45 4e 20 45 58 49 54 4c 4f 4f 50}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 [0-31] 20 00 28 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-31] 20 3d 20 [0-31] 20 28 20 22}  //weight: 1, accuracy: Low
        $x_1_7 = "&= EXECUTE ( \"Stri\" & \"ngL\" & \"eft(S\" & \"tringTri\" & \"mLeft(" ascii //weight: 1
        $x_1_8 = "5940530" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NOR_2147931297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NOR!MTB"
        threat_id = "2147931297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-31] 20 00 26 00 20 00 22 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 [0-31] 22 00 2c 00 20 00 31 00 38 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 20 45 58 45 43 55 54 45 20 28 20 24 [0-31] 20 26 20 22 28 40 54 65 6d 70 44 69 72 20 26 20 22 [0-31] 22 2c 20 31 38 29 22 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = "415840504158405x4158405541584055415840584158405b4158405e" ascii //weight: 1
        $x_1_4 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 [0-31] 20 00 28 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-31] 20 3d 20 [0-31] 20 28 20 22}  //weight: 1, accuracy: Low
        $x_1_6 = "405c4158405c415840504158405241584050" ascii //weight: 1
        $x_1_7 = "4158405" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_AMDE_2147932058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AMDE!MTB"
        threat_id = "2147932058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXECUTE ( \"Call\" )" ascii //weight: 1
        $x_3_2 = {26 00 3d 00 20 00 24 00 [0-21] 20 00 28 00 20 00 22 00 43 00 68 00 72 00 22 00 20 00 2c 00 20 00 24 00 00 20 00 28 00 20 00 22 00 41 00 73 00 63 00 22 00 20 00 2c 00 20 00 24 00 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_3 = {26 3d 20 24 [0-21] 20 28 20 22 43 68 72 22 20 2c 20 24 00 20 28 20 22 41 73 63 22 20 2c 20 24 00 20 28 20 22 53 74 72 69 6e 67 4d 69 64 22 20 2c 20 24 [0-21] 20 2c 20 24 [0-21] 20 2c 20 31 20 29}  //weight: 3, accuracy: Low
        $x_2_4 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_5 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_6 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-21] 20 00 28 00 20 00 22 00 52 00 76 00 7a 00 74 00 62 00 76 00 73 00 77 00 22 00 20 00 2c 00 20 00 31 00 31 00 20 00 29 00 20 00 2c 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 00 20 00 28 00 20 00 22 00}  //weight: 2, accuracy: Low
        $x_2_7 = {43 41 4c 4c 20 28 20 [0-21] 20 28 20 22 52 76 7a 74 62 76 73 77 22 20 2c 20 31 31 20 29 20 2c 20 43 41 4c 4c 20 28 20 00 20 28 20 22}  //weight: 2, accuracy: Low
        $x_2_8 = {28 00 20 00 22 00 50 00 79 00 7a 00 52 00 71 00 7d 00 7e 00 22 00 20 00 2c 00 20 00 31 00 31 00 20 00 29 00 20 00 2c 00 20 00 [0-21] 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 31 00 31 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00 6e 00 7c 00 7d 00 7b 00 22 00 20 00 2c 00 20 00 31 00 31 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00}  //weight: 2, accuracy: Low
        $x_2_9 = {28 20 22 50 79 7a 52 71 7d 7e 22 20 2c 20 31 31 20 29 20 2c 20 [0-21] 20 28 20 22 [0-30] 22 20 2c 20 31 31 20 29 20 2c 20 00 20 28 20 22 6e 7c 7d 7b 22 20 2c 20 31 31 20 29 20 2c 20 00 20 28 20 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_AYKA_2147933106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.AYKA!MTB"
        threat_id = "2147933106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR &" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_2_3 = "k5058815630er5058815630nel350588156302" ascii //weight: 2
        $x_2_4 = "5058815630V5058815630ir5058815630tualA5058815630llo5058815630c" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FormBook_NFA_2147933255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NFA!MTB"
        threat_id = "2147933255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = "5058815630" ascii //weight: 1
        $x_1_4 = {43 00 4f 00 4e 00 53 00 4f 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-31] 20 00 5b 00 20 00 24 00 [0-31] 20 00 5d 00 20 00 5b 00 20 00 30 00 20 00 5d 00 20 00 26 00 20 00 22 00 20 00 22 00 20 00 26 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 4f 4e 53 4f 4c 45 57 52 49 54 45 20 28 20 24 [0-31] 20 5b 20 24 [0-31] 20 5d 20 5b 20 30 20 5d 20 26 20 22 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_6 = {49 00 46 00 20 00 24 00 [0-31] 20 00 3c 00 3e 00 20 00 2b 00 20 00 2d 00 31 00 20 00 41 00 4e 00 44 00 20 00 24 00 [0-31] 20 00 3c 00 3e 00 20 00 2b 00 20 00 2d 00 31 00 20 00 54 00 48 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_7 = {49 46 20 24 [0-31] 20 3c 3e 20 2b 20 2d 31 20 41 4e 44 20 24 [0-31] 20 3c 3e 20 2b 20 2d 31 20 54 48 45 4e}  //weight: 1, accuracy: Low
        $x_1_8 = {49 00 46 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 2b 00 20 00 2d 00 31 00 20 00 4f 00 52 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 2b 00 20 00 2d 00 31 00 20 00 54 00 48 00 45 00 4e 00 20 00 52 00 45 00 54 00 55 00 52 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_9 = {49 46 20 24 [0-31] 20 3d 20 2b 20 2d 31 20 4f 52 20 24 [0-31] 20 3d 20 2b 20 2d 31 20 54 48 45 4e 20 52 45 54 55 52 4e}  //weight: 1, accuracy: Low
        $x_1_10 = "( \"H\" , \"Hydrogen\" , 10 )" ascii //weight: 1
        $x_1_11 = "( \"HCl\" , \"Hydrochloric Acid\" , \"aqueous\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NMD_2147936950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NMD!MTB"
        threat_id = "2147936950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 32 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 4f 43 41 4c 20 24 [0-31] 20 3d 20 4d 4f 44 20 28 20 24 [0-31] 20 2c 20 32 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = "REGDELETE ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "= EXECUTE ( \"B\" & \"i\" & \"n\" & \"a\" & \"r\" & \"y\" & \"L\" & \"e\" & \"n\" )" ascii //weight: 1
        $x_1_7 = "SlowrdiDiolf" ascii //weight: 1
        $x_1_8 = "hhoqbo05" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NAZ_2147939247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NAZ!MTB"
        threat_id = "2147939247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-31] 20 00 28 00 20 00 22 00 41 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 22 00 20 00 2c 00 20 00 24 00 [0-31] 20 00 28 00 20 00 22 00 53 00 74 00 22 00 20 00 26 00 20 00 22 00 72 00 22 00 20 00 26 00 20 00 22 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 4d 00 69 00 22 00 20 00 26 00 20 00 22 00 64 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-31] 20 28 20 22 41 73 22 20 26 20 22 63 22 20 2c 20 24 [0-31] 20 28 20 22 53 74 22 20 26 20 22 72 22 20 26 20 22 69 6e 22 20 26 20 22 67 4d 69 22 20 26 20 22 64 22}  //weight: 1, accuracy: Low
        $x_1_5 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "b@MMvH\" & \"OENVqSNB" ascii //weight: 1
        $x_1_7 = "wHSUT@\" & \"MqSNUDBU" ascii //weight: 1
        $x_1_8 = "EXECUTE ( \"C\" & \"a\" & \"l\" & \"l\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_NAY_2147939788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.NAY!MTB"
        threat_id = "2147939788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-31] 20 00 28 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-31] 20 28}  //weight: 1, accuracy: Low
        $x_1_5 = "( \"eGJJqOH\" & \"BIQv\" & \"TIE\" )" ascii //weight: 1
        $x_1_6 = "( \"pOTR\" & \"SGJvTI\" & \"RCER\" )" ascii //weight: 1
        $x_1_7 = "EXECUTE ( \"C\" & \"a\" & \"l\" & \"l\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FormBook_ZC_2147940907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormBook.ZC!MTB"
        threat_id = "2147940907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 34 1c 7b e1}  //weight: 1, accuracy: High
        $x_1_2 = {68 38 2a 90 c5}  //weight: 1, accuracy: High
        $x_1_3 = {68 53 d8 7f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


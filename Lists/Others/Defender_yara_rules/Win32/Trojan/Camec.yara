rule Trojan_Win32_Camec_A_2147637846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.A"
        threat_id = "2147637846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "637675757364101A1076627F7D1063617C656074716475106778756275107A0367110D1910626268637B757C661F" wide //weight: 1
        $x_1_2 = "78787C696F737C71636375636F627F7F646C4358545F565C5143581E4358532D556D735544585364" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Camec_A_2147637847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.gen!A"
        threat_id = "2147637847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "60415646595455420D63617C7F7C7574720B7451445110635F45425355" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_B_2147648925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.B"
        threat_id = "2147648925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "425F5B58525941450F4E5A5541534A4B5C5B54415D5E5F7954405D5F0A5A5B455747405A5F5444504C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_B_2147651844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.gen!B"
        threat_id = "2147651844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "626556475C444118665D56545D" wide //weight: 1
        $x_1_2 = "7D7D706C6A787A7574796C7570757071" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_C_2147652316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.C"
        threat_id = "2147652316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E9E88A24173234EEF96CB12B0B922259" wide //weight: 1
        $x_1_2 = "C1079317D40411FDC9CF0B16B25F7CAE  673FAC27799C4CCC81564989BC2E7726" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_D_2147652317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.D"
        threat_id = "2147652317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 00 37 00 36 00 38 00 37 00 26 00 a8 00 53 00 37 00 36 00 73 00 a8 00 25 00 24 00 34 00 35 00 33 00 32 00 33 00 34 00 35 00 36 00 37 00 21 00 40 00 23 00 24 00 25 00}  //weight: 1, accuracy: High
        $x_1_2 = "5A445108" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_E_2147652479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.E"
        threat_id = "2147652479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5D4241450F1B1A" wide //weight: 1
        $x_1_2 = "560C69425C5A515942466F" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_F_2147652809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.F"
        threat_id = "2147652809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7D7D706C6A787A7574796C75707570717D7069667B77656270647D6F7A5A55475D465C534569675C5F515D42406977404741565840655041455A585F6A6A44" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_G_2147652813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.G"
        threat_id = "2147652813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6B727572756D18" wide //weight: 1
        $x_1_2 = "62757472756319" wide //weight: 1
        $x_1_3 = "6B787F6361786A7C6D7D5E5242564A5657456F66595E555F43426C" wide //weight: 1
        $x_1_4 = "627F7E6361766B746E7C5F554A5C425D54456C675E5D5C5A46426C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Camec_H_2147653914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.H"
        threat_id = "2147653914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3b f3 0f 8c ?? 00 00 00 66 6b ff 40 66 8b 45 dc 0f 80 ?? 01 00 00 66 03 fe 0f 80 ?? 01 00 00 66 05 06 00 0f 80 ?? 01 00 00 66 3d 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {51 ff d6 6a ?? 8d ?? ?? ?? ff ff ?? ff d6 6a ?? 8d ?? ?? ?? ff ff ?? ff d6 6a ?? 8d ?? ?? ?? ff ff ?? ff d6 6a}  //weight: 1, accuracy: Low
        $x_1_3 = "FIObjectWithSite_SetSite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_I_2147653915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.I"
        threat_id = "2147653915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3b f3 0f 8c ?? 00 00 00 66 6b ff 40 66 8b 45 dc 0f 80 ?? 01 00 00 66 03 fe 0f 80 ?? 01 00 00 66 05 06 00 0f 80 ?? 01 00 00 66 3d 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = "T_PegaJanelaComandos" ascii //weight: 1
        $x_1_3 = "Extrato_001J" ascii //weight: 1
        $x_1_4 = "E_Giro_Rapido" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Camec_J_2147654968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.J"
        threat_id = "2147654968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "150A415115435C52415D0E1A040648401115150B39" wide //weight: 1
        $x_1_2 = "094251151555595F525B0E1A435F5F504717150B393B0D515840185A530E14515B43515B454612" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Camec_K_2147656355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Camec.K"
        threat_id = "2147656355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "F_ConvertXToDVD" ascii //weight: 1
        $x_1_2 = "T_Empresario" ascii //weight: 1
        $x_1_3 = "Func_Razao" ascii //weight: 1
        $x_1_4 = "UGT_Decio" ascii //weight: 1
        $x_10_5 = {66 3b f3 0f 8c ?? 00 00 00 66 6b ff 40 66 8b 45 dc 0f 80 ?? 01 00 00 66 03 fe 0f 80 ?? 01 00 00 66 05 06 00 0f 80 ?? 01 00 00 66 3d 08 00 89 45 dc 0f 8c ?? 00 00 00 0f bf f7 8d 55 dc 66 2d 08 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


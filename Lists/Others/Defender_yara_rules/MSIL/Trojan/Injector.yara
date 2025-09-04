rule Trojan_MSIL_Injector_W_2147711338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.W!bit"
        threat_id = "2147711338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 07 8e b7 5d 0d 02 08 02 08 91 07 09 91 61 9c 08 17 58 0c}  //weight: 2, accuracy: High
        $x_2_2 = "INSERT INTO employee(Employee Name, IC Number, HP Number, Address) Values ('" wide //weight: 2
        $x_1_3 = "c:\\test\\Contacts.txt" wide //weight: 1
        $x_1_4 = "c:\\test\\ContactsReport.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Injector_W_2147711466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.W"
        threat_id = "2147711466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 25 0d 2c 05 09 8e 69 2d 05 16 e0 0a 2b 08 09 16 8f ?? 00 00 01 0a 28 ?? 00 00 06 25 13 04 2c 06 11 04 8e 69 2d 05 16 e0 0b 2b 09 11 04 16 8f ?? 00 00 01 0b 16 0c 2b 1d 06 d3 08 58 06 d3 08 58 47 07 d3 08 28 ?? 00 00 06 8e 69 5d 58 47 61 d2 52 08 17 58 0c 08 02 8e 69 32 dd 16 e0 0a 16 e0 0b 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {06 19 5a 19 33 17 02 7b 03 00 00 04 74 ?? 00 00 01 6f ?? 00 00 0a 06 9a 28 ?? 00 00 06 06 17 58 0a 06 18 32}  //weight: 1, accuracy: Low
        $x_1_3 = {13 04 16 13 05 2b 5c 11 04 11 05 9a 0c 08 6f ?? 00 00 0a 6f ?? 00 00 0a 1e 33 42 08 6f ?? 00 00 0a 8e 69 17 33 37 08 6f ?? 00 00 0a 16 9a 6f ?? 00 00 0a d0 ?? 00 00 01 28 ?? 00 00 0a 33 1e 08 07 17 8d 01 00 00 01 13 06 11 06 16 03 a2 11 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_Y_2147711467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.Y"
        threat_id = "2147711467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 28 0e 00 00 0a 02 22 00 00 c0 40 22 00 00 50 41 73 0f 00 00 0a 28 10 00 00 0a 02 17 28 11 00 00 0a 02 20 1b 01 00 00 1f 34 73 12 00 00 0a 28 13 00 00 0a 02 72 09 00 00 70 28 14 00 00 0a 02 16 28 15 00 00 0a 02 72}  //weight: 1, accuracy: High
        $x_1_2 = {7e 07 00 00 04 25 0d 2c 05 09 8e 69 2d 05 16 e0 0a 2b 08 09 16 8f 18 00 00 01 0a 7e 06 00 00 04 25 13 04 2c 06 11 04 8e 69 2d 05 16 e0 0b 2b 09 11 04 16 8f 18 00 00 01 0b 16 0c 2b 1d 06 d3 08 58 06 d3 08 58 47 07 d3}  //weight: 1, accuracy: High
        $x_1_3 = {04 6f 1b 00 00 0a 8e 69 0a 16 0b 2b 4f 04 6f 1b 00 00 0a 07 9a 0c 08 6f 1d 00 00 0a 72 ?? 00 00 70 28 1e 00 00 0a 2c 30 08 6f 1f 00 00 0a 8e 69 17 33 25 08 6f 1f 00 00 0a 16 9a 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_Z_2147711523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.Z"
        threat_id = "2147711523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 25 0d 2c 05 09 8e 69 2d 05 16 e0 0a 2b 08 09 16 8f ?? 00 00 01 0a 28 ?? 00 00 06 25 13 04 2c 06 11 04 8e 69 2d 05 16 e0 0b 2b 09 11 04 16 8f ?? 00 00 01 0b 16 0c 2b 1d 06 d3 08 58 06 d3 08 58 47 07 d3 08 28 ?? 00 00 06 8e 69 5d 58 47 61 d2 52 08 17 58 0c 08 02 8e 69 32 dd 16 e0 0a 16 e0 0b 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {09 11 04 9a 0b 07 6f ?? 00 00 0a 6f ?? 00 00 0a 1a 33 ?? 07 6f ?? 00 00 0a 16 9a 6f ?? 00 00 0a d0 01 00 00 1b 28 ?? 00 00 0a 33}  //weight: 1, accuracy: Low
        $x_1_3 = {06 19 5a 19 33 17 02 7b 03 00 00 04 74 ?? 00 00 01 6f ?? 00 00 0a 06 9a 28 ?? 00 00 06 06 17 58 0a 06 18 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_Y_2147711573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.Y!bit"
        threat_id = "2147711573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 00 6f 00 5f 00 6e 00 69 00 2e 00 50 00 6e 00 67 00 [0-16] 4b 00 69 00 6d 00 5f 00 4f 00 2e 00 50 00 6e 00 67 00 [0-16] 4c 00 6f 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8e b7 17 da 11 04 da 02 11 04 91 ?? 61 ?? 11 04 ?? 8e b7 5d 91 61 9c 11 04 17 d6 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SA_2147712468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SA!bit"
        threat_id = "2147712468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "jiaowupaike" ascii //weight: 1
        $x_2_2 = {08 09 1e 58 91 08 09 91 1a 58 33 ?? 08 09 1c 58 91 08 09 91 19 58 33 ?? 08 09 18 58 91 08 09 91 17 58 33 ?? 08 09 1a 58 91 08 09 91 18 58 33 ?? 16 13 04}  //weight: 2, accuracy: Low
        $x_2_3 = {06 11 04 08 18 11 04 5a 09 58 1f 0a 58 91 08 09 1b 58 91 [0-5] 61 d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SB_2147712627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SB!bit"
        threat_id = "2147712627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 08 1b 58 07 8e 69 58 [0-4] 5f 63 20 ff 00 00 00 5f d2 61 d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = "A3dq3dee54f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SC_2147716530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SC!bit"
        threat_id = "2147716530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 20 ff 00 00 00 5f d2 13 [0-128] 7e ?? 00 00 04 ?? ?? 11 ?? 61 d2 9c [0-3] 58}  //weight: 1, accuracy: Low
        $x_1_2 = {46 00 6f 00 72 00 6d 00 31 00 ?? ?? 53 00 69 00 73 00 74 00 69 00 6d 00 65 00 74 00 6f 00 20 00 49 00 6e 00 63 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SF_2147716649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SF!bit"
        threat_id = "2147716649"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 09 00 00 04 06 1f ?? 5d 91 07 1f 1f 5f 63 0d 09 20 ff 00 00 00 5f d2 13 04 7e 08 00 00 04 06 08 11 04 61 d2 9c 06 17 58 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "Sistimeto coudn't load the sistem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SG_2147716904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SG!bit"
        threat_id = "2147716904"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FruitDeMer.key_zebi.wbp" wide //weight: 1
        $x_1_2 = "FruitDeMer.ressource_zebi.wbp" wide //weight: 1
        $x_1_3 = "sormomou1" ascii //weight: 1
        $x_1_4 = "$3c14b5a4-9d4e-43bd-82da-381bc782a68a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SH_2147716958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SH!bit"
        threat_id = "2147716958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Mitten" wide //weight: 1
        $x_1_2 = "Virto" wide //weight: 1
        $x_1_3 = {06 1b 58 7e [0-6] 8e 69 58 ?? 7e [0-7] 91 ?? 7e [0-7] 1f 1d 5d 91 ?? 1f 1f 5f 63 ?? ?? 28 [0-6] 13 04 7e [0-8] 11 04 28 [0-6] 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SI_2147717113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SI!bit"
        threat_id = "2147717113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Powered by SmartAssembly" ascii //weight: 1
        $x_1_2 = {23 00 66 00 6f 00 6c 00 64 00 65 00 72 00 23 00 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {23 00 66 00 6f 00 6c 00 64 00 65 00 72 00 23 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 23 00 3a 00 5a 00 6f 00 6e 00 65 00 2e 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 23 00 66 00 6f 00 6c 00 64 00 65 00 72 00 23 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 23 00 22 00 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SJ_2147717384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SJ!bit"
        threat_id = "2147717384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lost your game" wide //weight: 1
        $x_1_2 = {4c 00 6f 00 73 00 74 00 [0-16] 50 00 6c 00 61 00 79 00 [0-16] 57 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {06 11 04 06 11 04 91 ?? 11 04 07 5d 91 61 9c 11 04 17 d6 13 04}  //weight: 1, accuracy: Low
        $x_1_4 = {02 03 04 16 04 8e b7 28 3a 00 00 0a 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SN_2147717906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SN!bit"
        threat_id = "2147717906"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 1f 1d 5d 91 09 1f 1f 5f 63 13 05 11 05 28 ?? ?? ?? ?? 13 06 07 08 11 04 11 06 28 ?? ?? ?? ?? 9c 08 17 58 0c}  //weight: 2, accuracy: Low
        $x_1_2 = "Jospek" wide //weight: 1
        $x_1_3 = "GuvtHkikdRynWSroDuCwKGxdywAGu" wide //weight: 1
        $x_1_4 = "aJEpUjMbXGxAFSI12hZ408PQzLGsoTCUUQO29AaU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Injector_SO_2147717909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SO!bit"
        threat_id = "2147717909"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f d8 06 1e 63 d6 0a 08 1d d6 07 20 ff 00 00 00 5f d8 07 1e 63 d6 0b 06 1e 62 07 d6 20 ff 00 00 00 5f 0c 11 04 11 06 02 11 06 91 08 b4 61}  //weight: 1, accuracy: High
        $x_1_2 = {47 5a 69 70 53 74 72 65 61 6d 00 53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 76 65 6e 5a 69 70 48 65 6c 70 65 72 00 53 65 76 65 6e 5a 69 70 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 4c 5a 4d 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SM_2147717913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SM!bit"
        threat_id = "2147717913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 00 6e 00 2d 00 69 00 6e 00 74 00 [0-16] 74 00 72 00 79 00 50 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "ehehehehey" wide //weight: 1
        $x_1_3 = "gabbermerda" ascii //weight: 1
        $x_1_4 = {09 11 0b 09 11 0b 91 11 ?? 11 0b 11 04 5d 91 61 9c 11 0b 17 d6 13 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SQ_2147719215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SQ!bit"
        threat_id = "2147719215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System halted" wide //weight: 1
        $x_1_2 = {56 65 72 69 66 69 63 61 74 6f 72 00 62 6c 75 72 00 62 00}  //weight: 1, accuracy: High
        $x_1_3 = "Exists in the current dir of the system" wide //weight: 1
        $x_1_4 = {07 91 06 61 d2 9c 07 17 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SS_2147721717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SS!bit"
        threat_id = "2147721717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 61 00 74 00 61 00 32 00 2e 00 62 00 61 00 74 00 [0-32] 64 00 61 00 73 00 69 00 6f 00 68 00 6e 00 64 00 61 00 73 00 64 00 61 00 73 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "#newtmp#$$$.exe$$$" wide //weight: 1
        $x_1_3 = "fsfsdfsdfsdfsdf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_QA_2147741595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.QA!MTB"
        threat_id = "2147741595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 20 7e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5d 91 10 01 02 06 02 06 91 03 61 28 ?? ?? ?? ?? 9c 06 17 58 0a 06 02 8e 69 32 da 02 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {13 30 02 00 4b 00 00 00 01 00 00 11 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 0a 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 8e 69 80 ?? ?? ?? ?? 06 20 b0 00 00 00 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_A_2147742445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.A!ibt"
        threat_id = "2147742445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 28 ?? ?? ?? ?? 02 07 69 9a 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 0d 09 16 06 08 09 8e 69 17 59 28 ?? ?? ?? ?? 08 09 8e 69 17 59 58 0c 07 23 00 00 00 00 00 00 f0 3f 58 0b 07 02 8e 69 6c 32 ?? 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {06 07 06 07 91 1f ?? 61 d2 9c 07 17 58 0b 07 06 8e 69 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_B_2147742640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.B!ibt"
        threat_id = "2147742640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 0e 06 07 06 07 91 1f ?? 61 d2 9c 07 17 58 0b 07 06 8e 69 32 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_RB_2147748680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.RB!MSR"
        threat_id = "2147748680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 1f 10 07 16 07 8e b7 28 ?? ?? ?? 0a 16 07 8e b7 17 da 0d 0c 2b 11 07 08 07 08 91 02 08 1f 10 5d 91 61 9c 08 17 d6 0c 08 09 31 eb 07 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_RC_2147751353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.RC!MSR"
        threat_id = "2147751353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\Users\\Jamie\\Documents\\Visual Studio 2008\\Projects\\WindowsApplication15\\WindowsApplication15\\obj\\Release\\WindowsApplication15.pdb" ascii //weight: 5
        $x_5_2 = "WriteProcessMemory" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_M_2147767568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.M!MTB"
        threat_id = "2147767568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sof.tware\\Micr.osoft\\Win.dows\\Curr.entVer.sion\\.R.u.n\\" wide //weight: 1
        $x_1_2 = "%US.ERP.ROF.ILE.%\\A.ppD.ata.\\Ro.am.in.g\\.Mi.cr.os.of.t\\.Wind.ows\\.Star.t. Me.nu\\P.rog.rams\\" wide //weight: 1
        $x_1_3 = "S.of.tw.ar.e\\.Mi.cr.os.of.t.\\.W.i.ndow.s\\Cur.rentV.ersio.n\\Exp.lorer.\\User. She.ll .Fold.e.rs" wide //weight: 1
        $x_5_4 = "Select * from Win32_ComputerSystem" wide //weight: 5
        $x_5_5 = "SbieDll.dll" wide //weight: 5
        $x_5_6 = "AvastUI" wide //weight: 5
        $x_5_7 = "Am.si.Sc.an.Bu.ff.er" wide //weight: 5
        $x_1_8 = "CreateObject(\"WScript.Shell\").Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_MK_2147771659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.MK!MTB"
        threat_id = "2147771659"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ResumeThread_API" ascii //weight: 1
        $x_1_2 = "NtUnmapViewOfSection_API" ascii //weight: 1
        $x_1_3 = "CreateProcess_API" ascii //weight: 1
        $x_1_4 = "Wow64GetThreadContext_API" ascii //weight: 1
        $x_1_5 = "Wow64SetThreadContext_API" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx_API" ascii //weight: 1
        $x_1_7 = "ReadProcessMemory_API" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory_API" ascii //weight: 1
        $x_1_9 = "STARTUP_INFORMATION" ascii //weight: 1
        $x_1_10 = "PROCESS_INFORMATION" ascii //weight: 1
        $x_1_11 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_12 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_13 = "ObfuscatedByGoliath" ascii //weight: 1
        $x_1_14 = "NineRays.Obfuscator.Evaluation" ascii //weight: 1
        $x_1_15 = "get_WebServices" ascii //weight: 1
        $x_1_16 = "get_Settings" ascii //weight: 1
        $x_1_17 = "get_Controls" ascii //weight: 1
        $x_1_18 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_CH_2147775594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.CH!MTB"
        threat_id = "2147775594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunPe" ascii //weight: 1
        $x_1_2 = "ProcessInformation" ascii //weight: 1
        $x_1_3 = "StartupInformation" ascii //weight: 1
        $x_1_4 = "<Module>" ascii //weight: 1
        $x_1_5 = "<PrivateImplementationDetails>" ascii //weight: 1
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_7 = "IntPtr" ascii //weight: 1
        $x_1_8 = "UInt32" ascii //weight: 1
        $x_1_9 = "CreateProcess" ascii //weight: 1
        $x_1_10 = "GetThreadContext" ascii //weight: 1
        $x_1_11 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_12 = "SetThreadContext" ascii //weight: 1
        $x_1_13 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_14 = "ReadProcessMemory" ascii //weight: 1
        $x_1_15 = "WriteProcessMemory" ascii //weight: 1
        $x_1_16 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_17 = "VirtualAllocEx" ascii //weight: 1
        $x_1_18 = "ResumeThread" ascii //weight: 1
        $x_1_19 = "ToInt32" ascii //weight: 1
        $x_1_20 = "ToInt16" ascii //weight: 1
        $x_1_21 = "GetBytes" ascii //weight: 1
        $x_1_22 = "Buffer" ascii //weight: 1
        $x_1_23 = "BlockCopy" ascii //weight: 1
        $x_1_24 = "Process" ascii //weight: 1
        $x_1_25 = "GetProcessById" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_UUI_2147787055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.UUI!MTB"
        threat_id = "2147787055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<VAtoFileMapping>b__20_0" ascii //weight: 1
        $x_1_2 = "<RVAtoFileMapping>b__22_0" ascii //weight: 1
        $x_1_3 = "KeyValuePair" ascii //weight: 1
        $x_1_4 = "get_IsEXE" ascii //weight: 1
        $x_1_5 = "LoadConfig" ascii //weight: 1
        $x_1_6 = "ExecuteShellcodeInTargetProcess" ascii //weight: 1
        $x_1_7 = "OpenTargetProcess" ascii //weight: 1
        $x_1_8 = "InjectAssembly" ascii //weight: 1
        $x_1_9 = "Local injection" ascii //weight: 1
        $x_1_10 = "$2e3d8c82-eb96-4e17-9b03-fe13324e81b6" ascii //weight: 1
        $x_1_11 = "LoadAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_QWER_2147799511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.QWER!MTB"
        threat_id = "2147799511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JitHelpers.Ms3dLoader" ascii //weight: 1
        $x_1_2 = "ResumeLayout" ascii //weight: 1
        $x_1_3 = "MutexCreator" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "Your file was successfully converted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_TSHP_2147807533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.TSHP!MTB"
        threat_id = "2147807533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 73 17 00 00 0a 16 73 12 00 00 0a 0a 20 00 10 00 00 8d 1a 00 00 01 0b 73 11 00 00 0a 0c 16 0d 06 07 16 20 00 10 00 00 6f ?? ?? ?? 0a 0d 09 16 31 09 08 07 16 09 6f ?? ?? ?? 0a 09 16 30 e1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_JAKS_2147807534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.JAKS!MTB"
        threat_id = "2147807534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 06 2c 45 06 8e 2c 41 06 73 1c 00 00 0a 0c 08 16 73 1d 00 00 0a 0d 09 73 1e 00 00 0a 13 04 11 04 6f ?? ?? ?? 0a 0b de 20 11 04 2c 07 11 04 6f ?? ?? ?? 0a dc 09 2c 06 09 6f ?? ?? ?? 0a dc 08 2c 06 08 6f ?? ?? ?? 0a dc 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_MDNT_2147807535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.MDNT!MTB"
        threat_id = "2147807535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 2b 00 00 0a 0a 28 ?? ?? ?? 0a 00 00 00 00 00 7e 02 00 00 04 6f ?? ?? ?? 0a 0a 02 06 1f 2d 28 ?? ?? ?? 06 0b 07 16 9a 0c 02 08 07 17 9a 28 ?? ?? ?? 06 0d 02 09 1f 20 28 ?? ?? ?? 06 13 04 73 34 00 00 0a 13 05 00 11 04 13 06 16 13 07 2b 41 11 06 11 07 9a 13 08 00 02 11 08 28 ?? ?? ?? 06 17 fe 04 16 fe 01 13 09 11 09 2c 1e 00 11 08 28 ?? ?? ?? 0a 13 0a 11 0a 28 ?? ?? ?? 0a 13 0b 11 05 11 0b 6f ?? ?? ?? 0a 00 00 00 11 07 17 58 13 07 11 07 11 06 8e 69 32 b7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_JAYS_2147807536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.JAYS!MTB"
        threat_id = "2147807536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "njnkjpknjRSETrdtifyUFyufytuYTify" ascii //weight: 2
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "CryptDeriveKey" ascii //weight: 1
        $x_2_4 = "OKPIJNBIUYGHVFCTYRFDErdtyrt" ascii //weight: 2
        $x_1_5 = "BlockCopy" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_2_7 = {00 62 79 74 65 73 00}  //weight: 2, accuracy: High
        $x_2_8 = {00 73 75 72 72 6f 67 61 74 65 50 72 6f 63 65 73 73 00}  //weight: 2, accuracy: High
        $x_1_9 = {00 76 61 6c 75 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 6b 65 79 00}  //weight: 1, accuracy: High
        $x_1_11 = "antiSandie" ascii //weight: 1
        $x_1_12 = "TheDec" ascii //weight: 1
        $x_1_13 = "MarshalAs" ascii //weight: 1
        $x_1_14 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_HMC_2147808414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.HMC!MTB"
        threat_id = "2147808414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ioooooooooooooooooooooooo" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "UIuiiuyorethuiytweuhiwtgeuhiwgre" ascii //weight: 1
        $x_1_4 = "ATSWriteNCPY" ascii //weight: 1
        $x_1_5 = "IIUUYIRDRDIUUI" ascii //weight: 1
        $x_1_6 = "Iytuuyrfeuioygrfeiuohygrfeuhioegruih" ascii //weight: 1
        $x_1_7 = "XORDecrypt" ascii //weight: 1
        $x_1_8 = "ToString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NPMP_2147808636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NPMP!MTB"
        threat_id = "2147808636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 19 5a 8d 21 00 00 01 0a 16 0b 02 6f ?? ?? ?? 0a 17 59 0d 2b 5a 00 16 13 04 2b 3f 00 02 11 04 09 6f ?? ?? ?? 0a 13 05 06 07 19 5a 18 58 12 05 28 ?? ?? ?? 0a 9c 06 07 19 5a 17 58 12 05 28 ?? ?? ?? 0a 9c 06 07 19 5a 12 05 28 ?? ?? ?? 0a 9c 07 17 58 0b 00 11 04 17 58 13 04 11 04 02 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d b1 00 09 17 59 0d 09 16 fe 04 16 fe 01 13 07 11 07 2d 99 06 16 28 ?? ?? ?? 0a 8d 21 00 00 01 0c 06 1a 08 16 08 8e 69 28 ?? ?? ?? 0a 00 08 13 08 2b 00 11 08 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_TNAP_2147809341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.TNAP!MTB"
        threat_id = "2147809341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 73 27 00 00 0a 0a 06 16 73 28 00 00 0a 0b 73 29 00 00 0a 0c 20 00 04 00 00 8d 32 00 00 01 0d 2b 2a 00 07 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 11 04 16 fe 02 16 fe 01 13 05 11 05 2c 02 2b 11 08 09 16 11 04 6f ?? ?? ?? 0a 00 00 17 13 06 2b d1 07 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 13 07 2b 00 11 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SO_2147809860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SO!MTB"
        threat_id = "2147809860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 1, accuracy: High
        $x_1_2 = "DinvokeProcessHollow2" ascii //weight: 1
        $x_1_3 = "VirusInfected" ascii //weight: 1
        $x_1_4 = "CanLoadFromDisk" ascii //weight: 1
        $x_1_5 = "LoadModuleFromDisk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_RPZ_2147811599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.RPZ!MTB"
        threat_id = "2147811599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe" wide //weight: 1
        $x_1_2 = "ProcessHollowing" ascii //weight: 1
        $x_1_3 = "ConsoleApp1" wide //weight: 1
        $x_1_4 = "A86DDBE07E163A9F92CC4FA8470F9C979EC8AC47" ascii //weight: 1
        $x_1_5 = "CREATE_SUSPENDED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_Injector_RPU_2147812916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.RPU!MTB"
        threat_id = "2147812916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3.120.153.105" wide //weight: 1
        $x_1_2 = "Server.txt" wide //weight: 1
        $x_1_3 = "Invoke" wide //weight: 1
        $x_1_4 = "EntryPoint" wide //weight: 1
        $x_1_5 = "1A0571712A2F303411151A162C0A02322A2F2B7F" wide //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "LateGet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_RPU_2147812916_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.RPU!MTB"
        threat_id = "2147812916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "OctoSniff_Install.log" wide //weight: 1
        $x_1_3 = "Reflection.Assembly" wide //weight: 1
        $x_1_4 = "GetByteArrayAsync" wide //weight: 1
        $x_1_5 = "Nkcjdzelzsmvtvgdchkpqwpw" wide //weight: 1
        $x_1_6 = "Sleep" wide //weight: 1
        $x_1_7 = "HttpClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NE_2147822943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NE!MTB"
        threat_id = "2147822943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 03 61 1f 10 59 06 7e 29 00 00 04 20 8a 00 00 00 7e 29 00 00 04 20 8a 00 00 00 91 7e 13 00 00 04 1f 5e 93 61 1f 3a 5f 9c 61 45 01 00 00 00 0d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {91 7e 11 00 00 04 06 91 7e 16 00 00 04 1f 1f 5f 62 06 61 7e 17 00 00 04 58 61 d2 9c 1c 0c 2b 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NEC_2147831359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NEC!MTB"
        threat_id = "2147831359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$4516E0E1-5C0E-4B4E-9A32-9E37E23E7426" ascii //weight: 5
        $x_5_2 = "YippHB.dll" ascii //weight: 5
        $x_4_3 = "8.87.0.406" wide //weight: 4
        $x_3_4 = "PPsxtqiU" ascii //weight: 3
        $x_3_5 = "PolwKb" ascii //weight: 3
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NI_2147837018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NI!MTB"
        threat_id = "2147837018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 6b 00 00 0a 02 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 73 ?? ?? ?? 0a 25 20 ?? ?? ?? 7d 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 25 20 ?? ?? ?? 7d 28 ?? ?? ?? 06 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {03 1f 10 28 0b 00 00 2b 28 ?? ?? ?? 2b 0b 03 1f 10 28 ?? ?? ?? 2b 03 8e 69 1f 10 59 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0c 06 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d}  //weight: 5, accuracy: Low
        $x_1_3 = "Fartsyphhqtwblw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NBL_2147896411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NBL!MTB"
        threat_id = "2147896411"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 58 20 ff 00 00 00 5f 0c 09 11 07 08 91 58 20 ff 00 00 00 5f 0d 11 07 08 91 13 09 11 07 08 11 07 09 91 9c 11 07 09 11 09 9c 11 06 11 04 11 07 11 07 08 91 11 07 09 91 58 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 11 04 17 58 13 04 11 04 11 0c 31 ad 11 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NL_2147898971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NL!MTB"
        threat_id = "2147898971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ayendonjeans.com/Zvejhoosrg.vdf" ascii //weight: 4
        $x_1_2 = "DynamicInvoke" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "HtmlDecode" ascii //weight: 1
        $x_1_5 = "InvokeCode" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_N_2147898977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.N!MTB"
        threat_id = "2147898977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {20 6b 64 db 7d 20 2d c7 79 78 61 20 68 35 cf 69 58 61 58 61 ?? ?? ?? ?? ?? 61 61 61 5f 62 0a 02}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_ABK_2147899447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.ABK!MTB"
        threat_id = "2147899447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0e 04 0b 07 17 2e 08 2b 00 07 18 2e 0b 2b 2f 00 02 03 5d 0c 08 0a 2b 2b 00 04 05 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 04 28 ?? ?? ?? ?? 05 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 2b 05 00 16 0a 2b 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NN_2147901672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NN!MTB"
        threat_id = "2147901672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Crypter\\AdelTutorials" ascii //weight: 5
        $x_5_2 = "Crypter\\server1" ascii //weight: 5
        $x_1_3 = "encrypted" ascii //weight: 1
        $x_1_4 = "GeneratePassword" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "AES_Decrypt" ascii //weight: 1
        $x_1_7 = "NtReadVirtualMemory" ascii //weight: 1
        $x_1_8 = "NtUnmapViewOfSection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NITA_2147921880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NITA!MTB"
        threat_id = "2147921880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0c 2b 01 00 02 74 ?? 00 00 01 08 20 00 04 00 00 d6 17 da 17 d6 8d ?? 00 00 01 28 ?? ?? 00 0a 74 ?? 00 00 1b 10 00 07 02 08 20 00 04 00 00 6f ?? ?? 00 0a 0d 08 09 d6 0c 09 20 00 04 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NITA_2147921880_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NITA!MTB"
        threat_id = "2147921880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 04 1f 0c 58 28 ?? 00 00 0a 0c 03 04 1f 10 58 28 ?? 00 00 0a 0d 03 04 1f 14 58 28 ?? 00 00 0a 13 04 09 2c 3e 09 8d 2f 00 00 01 13 05 03 11 04 11 05 16 11 05 8e 69 28 ?? 00 00 0a 7e 08 00 00 04 7e 02 00 00 04 7b 0a 00 00 04 02 08 58 11 05 11 05 8e 69 0f 03 6f ?? 00 00 06 2d 06 73 2e 00 00 0a 7a 04 1f 28 58 10 02 07 17 58 0b 07 06 32 8f}  //weight: 2, accuracy: Low
        $x_1_2 = "LogEncryptionResult" ascii //weight: 1
        $x_1_3 = "shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SWC_2147925563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SWC!MTB"
        threat_id = "2147925563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 04 00 00 04 03 02 7b 04 00 00 04 03 91 20 45 01 00 00 61 d2 9c 2a}  //weight: 2, accuracy: High
        $x_2_2 = {02 7e 14 00 00 0a 7d 01 00 00 04 02 28 ?? 00 00 0a 20 fc 05 00 00 28 ?? 00 00 0a 02 28 ?? 00 00 06 20 3c 15 00 00 28 ?? 00 00 0a 02 7b 03 00 00 04 72 01 00 00 70 6f ?? 00 00 0a 14 16 8d 1b 00 00 01 6f ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NIT_2147926331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NIT!MTB"
        threat_id = "2147926331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 1d 00 00 70 28 ?? 00 00 0a 72 31 00 00 70 72 45 00 00 70 28 ?? 00 00 06 00 02 28 ?? 00 00 0a 72 5b 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 72 73 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 00 28 ?? 00 00 0a 72 5b 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 28 ?? 00 00 0a 72 73 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 15 28 ?? 00 00 0a 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_NIT_2147926331_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.NIT!MTB"
        threat_id = "2147926331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 04 06 11 04 91 03 11 04 03 8e b7 5d 91 11 04 08 d6 03 8e b7 d6 1d 5f 62 d2 20 00 01 00 00 5d 61 b4 9c 11 04 17 d6 13 04 11 04 11 05 31 d0}  //weight: 2, accuracy: High
        $x_2_2 = {02 08 11 04 6f ?? 00 00 0a 0d 09 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 17 d6 13 04 11 04 11 06 31 b2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SWD_2147928352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SWD!MTB"
        threat_id = "2147928352"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0d 11 09 28 ?? 00 00 06 26 11 06 28 ?? 00 00 0a 13 0e 11 09 20 88 00 00 00 28 ?? 00 00 0a 13 0f 11 0c 11 0f 1f 10 6a 58 11 0e 1e 16 6a 28 ?? 00 00 06 26 11 09 20 80 00 00 00 11 06 09 6a 58 28 ?? 00 00 0a 00 11 0d 11 09 28 ?? 00 00 06 26 11 0d 28 ?? 00 00 06 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_MBWJ_2147929493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.MBWJ!MTB"
        threat_id = "2147929493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Pimycuhynaxaefanaetawae" ascii //weight: 2
        $x_1_2 = "Wyqijumylyshefishaepyky" ascii //weight: 1
        $x_1_3 = "eaf89bed.Resources" ascii //weight: 1
        $x_1_4 = "d5e9d5d0a34d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_AYA_2147930964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.AYA!MTB"
        threat_id = "2147930964"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 11 09 08 28 0d 00 00 06 5d 08 11 09 08 28 0d 00 00 06 5d 91 07 11 09 07 28 0d 00 00 06 5d 91 61 08 11 09 17 d6 08 28 0d 00 00 06 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 11 09 17 d6 13 09 11 09 11 08 31 b7}  //weight: 2, accuracy: High
        $x_1_2 = "HXX.Form1.resources" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_CDC_2147934833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.CDC!MTB"
        threat_id = "2147934833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 06 02 09 6f 1b 01 00 0a 03 09 6f 1b 01 00 0a 61 60 0a 00 09 17 58 0d 09 02 6f a6 00 00 0a fe 04 13 04 11 04 2d d9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_CDB_2147935601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.CDB!MTB"
        threat_id = "2147935601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {6a 5f 69 95 61 d2 9c 00 11 06 17 58 13 06 11 06 11 09 13 0b 11 0b 31 a3}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SWE_2147935625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SWE!MTB"
        threat_id = "2147935625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 0a 06 17 58 0a 06 1f 0f 31 f7 28 ?? 00 00 0a 72 b7 00 00 70 28 ?? 00 00 06 74 01 00 00 1b 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 06 20 e8 03 00 00 28 ?? 00 00 0a 2b f4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_SWF_2147935630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.SWF!MTB"
        threat_id = "2147935630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 02 26 16 2b 02 26 16 20 38 02 00 00 8d 01 00 00 01 25 d0 01 00 00 04 28 02 00 00 06 80 02 00 00 04 20 8a 00 00 00 8d 02 00 00 01 25 d0 03 00 00 04 28 02 00 00 06 80 04 00 00 04 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_EARW_2147936230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.EARW!MTB"
        threat_id = "2147936230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 06 11 04 9a 6f 61 00 00 0a 25 26 a2 11 04 17 58 13 04 09 17 58 0d 11 04 06 8e 69 32 e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_EAPQ_2147936729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.EAPQ!MTB"
        threat_id = "2147936729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 11 0c 16 11 0a 6f 44 00 00 0a 26 11 09 11 0c 16 11 0a 11 0b 16 6f 4f 00 00 0a 13 0e 7e 0a 00 00 04 11 0b 16 11 0e 6f 50 00 00 0a 11 0d 11 0a 58 13 0d 11 0d 11 0a 58 6a 03 6f 48 00 00 0a 32 bf}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injector_AHB_2147947693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.AHB!MTB"
        threat_id = "2147947693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {11 07 11 08 11 05 11 08 91 11 06 11 08 11 06 8e 69 5d 91 61 d2 9c 11 08 17 58 13 08 11 08 11 05 8e 69 3f d9 ff ff ff}  //weight: 30, accuracy: High
        $x_30_2 = {08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 3f e4 ff ff ff}  //weight: 30, accuracy: High
        $x_10_3 = {28 05 00 00 0a 13 06 11 05 8e 69 8d 06 00 00 01 13 07 16 13 08}  //weight: 10, accuracy: High
        $x_10_4 = {28 01 00 00 0a 0b 06 8e 69 8d 01 00 00 01 0c 16 0d 38 13 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_10_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Injector_AKQ_2147948431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injector.AKQ!MTB"
        threat_id = "2147948431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 05 28 2c 00 00 0a 13 08 11 06 28 2c 00 00 0a 13 09 11 07 11 08 11 09 28 12 00 00 06 13 0a 11 0a 28 2c 00 00 0a 13 0b 11 04 39 0f 00 00 00 72 65 02 00 70 80 01 00 00 04 38 0a 00 00 00 72 a5 02 00 70 80 01 00 00 04 73 01 00 00 06 13 0c 11 0c 7e 01 00 00 04 11 0b 6f 11 00 00 06 2a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_Moloterae_B_2147684220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Moloterae.B"
        threat_id = "2147684220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Moloterae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Main Nattly Novi\\" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 4c 69 6e 6b 4f 62 6a 65 63 74 00 49 53 68 65 6c 6c 4c 69 6e 6b 44 75 61 6c 32 00 73 65 74 5f 41 72 67 75 6d 65 6e 74 73}  //weight: 1, accuracy: High
        $x_1_3 = {45 78 74 52 65 73 65 74 2e 65 78 65 00 46 6f 72 6d 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Moloterae_C_2147684221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Moloterae.C"
        threat_id = "2147684221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Moloterae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wpudte\\obj\\Debug\\Process Host.pdb" ascii //weight: 1
        $x_1_2 = "NaSSy\\ExtReset.exe" wide //weight: 1
        $x_1_3 = {48 6f 73 74 2e 65 78 65 00 46 6f 72 6d 31 00 77 70 75 64 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Moloterae_D_2147684222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Moloterae.D"
        threat_id = "2147684222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Moloterae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LASTmAIN\\NATTLY" ascii //weight: 1
        $x_1_2 = {19 5c 00 77 00 75 00 64 00 70 00 70 00 74 00 65 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {1b 5c 00 45 00 78 00 74 00 52 00 65 00 73 00 65 00 74 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Moloterae_A_2147684224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Moloterae.A"
        threat_id = "2147684224"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Moloterae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://search.ueep.com/?q={searchTerms}" wide //weight: 1
        $x_1_2 = "http://www.nattly.com/favicon.ico" wide //weight: 1
        $x_1_3 = "mailRuSputnik.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Moloterae_E_2147684336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Moloterae.E"
        threat_id = "2147684336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Moloterae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.nattly.com/favicon.ico" wide //weight: 1
        $x_1_2 = {53 68 65 6c 6c 4c 69 6e 6b 4f 62 6a 65 63 74 00 49 53 68 65 6c 6c 4c 69 6e 6b 44 75 61 6c 32 00 73 65 74 5f 41 72 67 75 6d 65 6e 74 73}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 61 61 63 68 00 4e 61 69 67 65 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Moloterae_F_2147684337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Moloterae.F"
        threat_id = "2147684337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Moloterae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GuardMailRu" wide //weight: 1
        $x_1_2 = "\"browser.startup.homepage\"" wide //weight: 1
        $x_1_3 = "urls_to_restore_on_startup" wide //weight: 1
        $x_1_4 = {43 68 72 6f 6d 65 5f 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {4b 69 6c 6c 65 72 5f 46 6f 6c 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 72 6f 63 63 65 73 73 5f 44 69 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {76 5f 4f 6d 6e 69 62 6f 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


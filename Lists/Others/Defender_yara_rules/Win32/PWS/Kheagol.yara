rule PWS_Win32_Kheagol_B_2147624364_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kheagol.B"
        threat_id = "2147624364"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kheagol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 79 69 65 2e 65 78 65 [0-16] 6d 61 78 74 68 6f 6e 2e 65 78 65 [0-16] 61 76 61 6e 74 2e 65 78 65 00}  //weight: 2, accuracy: Low
        $x_1_2 = {73 65 61 6d 6f 6e 6b 65 79 2e 65 78 65 [0-16] 6d 6f 7a 69 6c 6c 61 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_5_3 = {50 52 5f 57 72 69 74 65 [0-16] 50 52 5f 43 6c 6f 73 65 00}  //weight: 5, accuracy: Low
        $x_5_4 = {50 46 58 49 6d 70 6f 72 74 43 65 72 74 53 74 6f 72 65 [0-16] 55 53 45 52 33 32 2e 44 4c 4c [0-16] 47 65 74 57 69 6e 64 6f 77 54 65 78 74 41 00}  //weight: 5, accuracy: Low
        $x_1_5 = {74 66 8b d2 c6 44 24 ?? 68 [0-1] c6 44 24 ?? 6f [0-1] c6 44 24 ?? 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {61 66 87 d2 c6 44 24 ?? 76 [0-3] c6 44 24 ?? 61 [0-2] c6 44 24 ?? 6e [0-2] c6 44 24 ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Kheagol_E_2147643637_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kheagol.E"
        threat_id = "2147643637"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kheagol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CREDUI.dll" ascii //weight: 3
        $x_3_2 = "startup.php?id=%s&ver=%u&btype=%u" ascii //weight: 3
        $x_3_3 = "data.php?id=%s&ver=%u&m=%u&btype=%u" ascii //weight: 3
        $x_3_4 = "idi=%u" ascii //weight: 3
        $x_2_5 = "CREDAT:" ascii //weight: 2
        $x_1_6 = "CredUIPromptForCredentials" ascii //weight: 1
        $x_1_7 = "PFXImportCertStore" ascii //weight: 1
        $x_1_8 = "data.php" ascii //weight: 1
        $x_1_9 = "startup.php" ascii //weight: 1
        $x_1_10 = {68 8d bd c1 3f}  //weight: 1, accuracy: High
        $x_1_11 = {c6 44 24 38 69}  //weight: 1, accuracy: High
        $x_1_12 = {68 37 bd 4f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Kheagol_D_2147643638_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kheagol.D"
        threat_id = "2147643638"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kheagol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {af aa bf aa e5 bb a3 bb f4 a2 af f6 ee b8 ed bd ae b9 f6 ee be ed a6 f6 ee be ed a9 bf b2 bb ae f6 ee be 00}  //weight: 5, accuracy: High
        $x_1_2 = "CREDUI.dll" ascii //weight: 1
        $x_1_3 = "CredUIPromptForCredentials" ascii //weight: 1
        $x_1_4 = "PFXImportCertStore" ascii //weight: 1
        $x_1_5 = {68 8d bd c1 3f}  //weight: 1, accuracy: High
        $x_1_6 = {68 37 bd 4f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Kheagol_G_2147649842_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kheagol.G"
        threat_id = "2147649842"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kheagol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data.php" ascii //weight: 1
        $x_1_2 = "a=%s&b=%s&c=%s" ascii //weight: 1
        $x_1_3 = {68 e3 ca 1d 56}  //weight: 1, accuracy: High
        $x_1_4 = {68 bd d9 e9 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


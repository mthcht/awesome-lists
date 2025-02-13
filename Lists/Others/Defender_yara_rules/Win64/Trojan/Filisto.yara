rule Trojan_Win64_Filisto_D_2147751734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filisto.D!dha"
        threat_id = "2147751734"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 4c 6f 61 64 65 72 44 4c 4c 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 4c 6f 61 64 65 72 44 4c 4c 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 53 74 61 72 74 55 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 45 76 6f 72 61 44 4c 4c 2e [0-4] 00 45 76 51 75 65 72 79 45 76 65 6e 74 00 45 76 53 65 72 76 69 63 65 45 76 65 6e 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 45 76 6f 72 61 44 4c 4c 2e 64 6c 6c [0-5] 45 76 53 65 72 76 69 63 65 45 76 65 6e 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 64 6c 6c 00 44 4f 43 00 50 44 46 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_6 = {00 4c 6f 61 64 44 4c 4c 34 2e 64 6c 6c 00 3f 3f 30 43 73 73 64 6c 6c 40 40 51 41 45 40 58 5a 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 3f 6e 73 73 64 6c 6c 40 40 33 48 41 00 53 65 72 76 69 63 65 4d 61 69 6e 00 53 74 61 72 74 55 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 3f 6e 73 73 64 6c 6c 40 40 33 48 41 00 53 74 61 72 74 55 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 4c 6f 61 64 65 72 46 75 6e 63 2e 64 6c 6c 00 49 6e 69 74 69 61 6c 69 7a 65 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Filisto_E_2147751735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filisto.E!dha"
        threat_id = "2147751735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "donotbotherme" ascii //weight: 2
        $x_2_2 = "FXSAPIDebugLogFile.tmp" ascii //weight: 2
        $x_2_3 = "Try Https by WPADProxy." ascii //weight: 2
        $x_1_4 = "Get FireFoxProxy %s" ascii //weight: 1
        $x_1_5 = "OpenHttpByNoProxy WinHttpOpen Failed! - %d" ascii //weight: 1
        $x_1_6 = "m_client_head Base64Encode fail!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Filisto_C_2147912107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filisto.C!dha"
        threat_id = "2147912107"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\system32\\midimap.DriverProc" ascii //weight: 1
        $x_1_2 = "c:\\windows\\system32\\midimap.modMessage" ascii //weight: 1
        $x_1_3 = "c:\\windows\\system32\\midimap.modmCallback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filisto_K_2147932634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filisto.K!dha"
        threat_id = "2147932634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filisto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c d4 00 00 [0-4] c7 81 60 d4 00 00 00 00 02 00 ?? ?? 68 d4 00 00 [0-7] (30|34|40) 28 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


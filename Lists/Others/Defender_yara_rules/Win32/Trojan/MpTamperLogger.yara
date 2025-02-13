rule Trojan_Win32_MpTamperLogger_T_2147776572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperLogger.T"
        threat_id = "2147776572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 00 65 00 67 00 [0-8] 20 00 [0-16] 61 00 64 00 64 00 20 00}  //weight: 3, accuracy: Low
        $x_3_2 = "\\control\\wmi\\autologger\\defenderauditlogger" wide //weight: 3
        $x_1_3 = {2f 00 76 00 20 00 [0-8] 73 00 74 00 61 00 72 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 76 00 20 00 [0-8] 65 00 6e 00 61 00 62 00 6c 00 65 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 00 64 00 20 00 [0-4] 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 00 64 00 20 00 [0-4] 32 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2f 00 64 00 20 00 [0-4] 33 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2f 00 64 00 20 00 [0-4] 34 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperLogger_P_2147776573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperLogger.P"
        threat_id = "2147776573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 00 65 00 67 00 [0-8] 20 00 [0-16] 61 00 64 00 64 00 20 00}  //weight: 3, accuracy: Low
        $x_3_2 = "\\control\\wmi\\autologger\\defenderapilogger" wide //weight: 3
        $x_1_3 = {2f 00 76 00 20 00 [0-8] 73 00 74 00 61 00 72 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 76 00 20 00 [0-8] 65 00 6e 00 61 00 62 00 6c 00 65 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 00 64 00 20 00 [0-4] 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 00 64 00 20 00 [0-4] 32 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2f 00 64 00 20 00 [0-4] 33 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2f 00 64 00 20 00 [0-4] 34 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


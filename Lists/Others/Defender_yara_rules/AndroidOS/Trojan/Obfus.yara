rule Trojan_AndroidOS_Obfus_B_2147832958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Obfus.B!MTB"
        threat_id = "2147832958"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Obfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 70 32 00 00 00 00 00 71 20 ?? ?? 04 00 00 00 00 00 0a 07 00 00 00 00 71 10 ?? ?? 01 00 00 00 00 00 0a 08 00 00 00 00 94 08 00 08 00 00 00 00 71 20 ?? ?? 81 00 00 00 00 00 0a 08 00 00 00 00 b7 87 00 00 00 00 8e 77 00 00 00 00 71 20 ?? ?? 76 00 00 00 00 00 d8 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Obfus_C_2147833362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Obfus.C!MTB"
        threat_id = "2147833362"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Obfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 64 02 00 5c c7 ?? ?? 48 04 08 02 b0 41 d5 11 ff 00 70 40 ?? ?? 8c 12 ?? ?? ?? ?? ?? ?? ?? ?? 48 04 08 02 48 05 08 01 b0 54 d5 44 ff 00 5c c7 ?? ?? 1a 05 ?? ?? 48 05 0d 00 48 04 08 04 b7 54 8d 44 4f 04 03 00 1a 04 ?? ?? 5b c4 ?? ?? d8 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Obfus_D_2147833642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Obfus.D!MTB"
        threat_id = "2147833642"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Obfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 25 58 00 08 04 25 00 07 40 07 03 71 10 1c 00 03 00 0c 03 07 30 14 0a 0f a3 35 03 28 01 14 0c fe 9a 00 00 97 0a 0a 0c 2c 0a 0c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 70 2f 6d 61 6e 61 67 65 72 2f [0-3] 63 6b 53 69 67 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Obfus_F_2147849006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Obfus.F!MTB"
        threat_id = "2147849006"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Obfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 7c 01 ad 07 7e 01 af 48 0e 0e 0f 07 4f 02 10 0a 00 02 11 09 00 94 10 10 11 74 02 2e 00 0f 00 0a 0f b7 fe 8d ee 4f 0e 0c 0d}  //weight: 1, accuracy: High
        $x_1_2 = {6e 70 2f 6d 61 6e 61 67 65 72 2f [0-3] 63 6b 53 69 67 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


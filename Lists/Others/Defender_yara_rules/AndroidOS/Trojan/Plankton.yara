rule Trojan_AndroidOS_Plankton_A_2147654279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Plankton.gen!A"
        threat_id = "2147654279"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Plankton"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 62 72 6f 77 73 65 72 2e 53 45 54 5f 48 4f 4d 45 50 41 47 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {12 49 12 38 12 27 12 16 12 05 22 00 ?? 00 1a 01 ?? 03 1a 02 ?? ?? 1a 03 ?? ?? 70 53 ?? ?? 10 25 69 00 ?? ?? 22 00 ?? ?? 1a 01 ?? ?? 1a 02 ?? ?? 1a 03 ?? ?? 70 53 ?? ?? 10 26 69 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Plankton_B_2147654554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Plankton.gen!B"
        threat_id = "2147654554"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Plankton"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 49 12 38 12 27 12 16 12 05 22 00 46 00 1a 01 0e 03 1a 02 76 03 1a 03 6d 01 70 53 ?? 00 10 25 69 00 3b 00 22 00 46 00 1a 01 20 02 1a 02 4f 02 1a 03 6b 01 70 53 ?? 00 10 26 69 00}  //weight: 1, accuracy: Low
        $x_1_2 = {22 00 46 00 1a 01 a0 02 1a 02 da 02 1a 03 6c 01 70 53 ?? 00 10 29 69 00 3a 00 22 00 46 00 1a 01 e1 0b 12 52 1a 03 29 0c 1a 04 73 01 70 54 ?? 00 10 32 69 00 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Plankton_C_2147654601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Plankton.gen!C"
        threat_id = "2147654601"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Plankton"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 63 6f 6d 2f 70 6c 61 6e 6b 74 6f 6e 2f 64 65 76 69 63 65 2f 61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 41 6e 64 72 6f 69 64 4d 44 4b 53 65 72 76 69 63 65 3b 00}  //weight: 10, accuracy: High
        $x_1_2 = {4c 63 6f 6d 2f 70 6c 61 6e 6b 74 6f 6e 2f 64 65 76 69 63 65 2f 61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 53 65 6e 64 53 74 61 74 75 73 54 61 73 6b 3b 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 6c 61 6e 6b 74 6f 6e 5f 75 70 67 72 61 64 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 63 6f 6d 2f 50 72 6f 74 6f 63 6f 6c 47 57 2f 70 72 6f 74 6f 63 6f 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 6f 6d 2f 70 6c 61 6e 6b 74 6f 6e 2f 64 65 76 69 63 65 2f 61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 61 3b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Plankton_B_2147684201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Plankton.B"
        threat_id = "2147684201"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Plankton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 62 72 6f 77 73 65 72 2e 53 45 54 5f 48 4f 4d 45 50 41 47 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {12 38 12 27 12 16 12 05 22 00 1a 01 1a 01 af 02 1a 02 e8 02 1a 03 bf 0c 70 53 ba 04 10 25 69 00 30 01 22 00 1a 01 1a 01 99 01 1a 02 c5 01 1a 03 c1 0c 70 53 ba 04 10 26 69 00 2e 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


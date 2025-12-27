rule Trojan_Win64_IceTamper_A_2147949019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IceTamper.A"
        threat_id = "2147949019"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IceTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 6e 74 69 6e 65 6c 41 67 65 6e 74 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? 53 65 6e 74 69 6e 65 6c 53 65 72 76 69 63 65 48 6f 73 74 2e 65 78 65 ?? 53 65 6e 74 69 6e 65 6c 53 74 61 74 69 63 45 6e 67 69 6e 65 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? 53 65 6e 74 69 6e 65 6c 55 49 2e 65 78 65 ?? ?? 53 65 6e 74 69 6e 65 6c 48 65 6c 70 65 72 53 65 72 76 69 63 65 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? 4d 73 53 65 6e 73 65 2e 65 78 65 ?? ?? ?? ?? ?? 53 65 6e 73 65 54 56 4d 2e 65 78 65 ?? ?? ?? ?? 53 65 6e 73 65 4e 64 72 2e 65 78 65 ?? ?? ?? ?? 53 65 6e 73 65 49 52 2e 65 78 65 ?? ?? ?? ?? ?? 4d 73 4d 70 45 6e 67 2e 65 78 65 ?? ?? ?? ?? ?? 4d 70 44 65 66 65 6e 64 65 72 43 6f 72 65 53 65 72 76 69 63 65 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IceTamper_B_2147949801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IceTamper.B"
        threat_id = "2147949801"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IceTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 65 6e 74 69 6e 65 6c 41 67 65 6e 74 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 65 6e 74 69 6e 65 6c 53 65 72 76 69 63 65 48 6f 73 74 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_3 = {53 65 6e 74 69 6e 65 6c 53 74 61 74 69 63 45 6e 67 69 6e 65 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_4 = {53 65 6e 74 69 6e 65 6c 55 49 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_5 = {53 65 6e 74 69 6e 65 6c 48 65 6c 70 65 72 53 65 72 76 69 63 65 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_6 = {4d 73 53 65 6e 73 65 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_7 = {53 65 6e 73 65 54 56 4d 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_8 = {53 65 6e 73 65 4e 64 72 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_9 = {53 65 6e 73 65 49 52 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_10 = {4d 73 4d 70 45 6e 67 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_11 = {4d 70 44 65 66 65 6e 64 65 72 43 6f 72 65 53 65 72 76 69 63 65 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_12 = {53 65 6e 73 65 43 6e 63 50 72 6f 78 79 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_13 = {53 65 6e 73 65 53 61 6d 70 6c 65 55 70 6c 6f 61 64 65 72 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_14 = {4d 70 43 6d 64 52 75 6e 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_15 = {4d 70 53 76 63 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_16 = {53 63 72 65 65 6e 43 6f 6e 6e 65 63 74 2e 43 6c 69 65 6e 74 53 65 72 76 69 63 65 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_17 = {42 64 41 70 69 55 74 69 6c 36 34 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_18 = {6b 73 61 70 69 36 34 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_19 = {73 79 73 6d 6f 6e 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_20 = {76 69 72 61 67 74 36 34 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_21 = {77 73 66 74 70 72 6d 2e 73 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_10_*) and 1 of ($x_1_*))) or
            ((11 of ($x_10_*))) or
            (all of ($x*))
        )
}


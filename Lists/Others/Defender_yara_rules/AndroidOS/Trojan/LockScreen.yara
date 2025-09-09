rule Trojan_AndroidOS_LockScreen_D_2147937879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockScreen.D!MTB"
        threat_id = "2147937879"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 06 07 17 15 08 03 7f 12 09 6e 30 15 00 87 09 0c 07 1f 07 14 00 5b 67 10 00 07 06 22 07 1a 00 07 7d 07 d7 07 d8 07 09 70 20 21 00 98 00 5b 67 0c 00 07 06 07 07 54 77 10 00 15 08 05 7f 6e 20 18 00 87 00 0c 07 1f 07 19 00 5b 67 0e 00 07 06 07 07 54 77 10 00 14 08 02 00 05 7f}  //weight: 1, accuracy: High
        $x_1_2 = {0c 04 07 42 07 24 1a 05 6a 00 13 06 80 00 6e 30 13 00 54 06 0c 04 07 43 22 04 3b 00 07 4a 07 a4 07 a5 22 06 01 00 07 6a 07 a6 07 a7 07 08 70 20 01 00 87 00 70 20 48 00 65 00 07 42 07 24 6e 10 49 00 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_LockScreen_E_2147938559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockScreen.E!MTB"
        threat_id = "2147938559"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 04 07 05 6e 10 08 00 05 00 0c 05 52 55 02 00 12 26 dd 05 05 02 32 54 08 00 12 14 01 41 01 14 39 04 05 00 28 e2 12 04 28 fa 07 04 6e 10 09 00 04 00 0c 04 07 42 07 24 1a 05 6a 00 13 06 80 00 6e 30 13 00 54 06 0c 04 07 43 22 04 3b 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 20 47 00 87 00 0a 07 38 07 1e 00 22 07 07 00 07 7e 07 e7 07 e8 07 19 1a 0a 6c 00 71 10 40 00 0a 00 0c 0a 70 30 0d 00 98 0a 07 74 07 47 15 08 00 10 6e 20 0e 00 87 00 0c 07 07 17 07 48 6e 20 0b 00 87 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_LockScreen_F_2147951872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockScreen.F!MTB"
        threat_id = "2147951872"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 09 72 00 71 10 4a 00 09 00 0c 09 70 30 12 00 87 09 07 63 07 36 15 07 00 10 6e 20 14 00 76 00 0c 06 07 16 07 37 6e 20 0f 00 76 00 0e 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 10 0c 00 04 00 0c 00 1a 02 71 00 13 03 80 00 6e 30 19 00 20 03 22 00 40 00 22 02 01 00 70 20 01 00 42 00 70 20 53 00 20 00 6e 10 54 00 00 00 28 d1 0d 00 1e 01 27 00 12 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Ampskerk_A_2147682395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ampskerk.A!dha"
        threat_id = "2147682395"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ampskerk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 3a 26 75 1b 66 83 38 4b 75 15 66 83 78 0e 73 75 0e 66 83 78 1e 4b}  //weight: 1, accuracy: High
        $x_1_2 = {41 bb 48 b8 00 00 66 44 89 1f 4c 89 77 02 c6 47 0a c3}  //weight: 1, accuracy: High
        $x_1_3 = {48 6f 6f 6b 44 43 2e 64 6c 6c 00 69 00 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ampskerk_B_2147691027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ampskerk.B!dha"
        threat_id = "2147691027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ampskerk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {66 83 3a 26 75 1b 66 83 38 4b 75 15 66 83 78 0e 73 75 0e 66 83 78 1e 4b}  //weight: 5, accuracy: High
        $x_3_2 = {48 6f 6f 6b 44 43 2e 64 6c 6c 00 69 00 75 00}  //weight: 3, accuracy: High
        $x_3_3 = {48 6f 6f 6b 44 43 2e 64 6c 6c 00 69 69 00 75 75 00}  //weight: 3, accuracy: High
        $x_1_4 = "samsrv.dll" ascii //weight: 1
        $x_1_5 = "cryptdll.dll" ascii //weight: 1
        $x_1_6 = "SamIRetrievePrimaryCredentials" ascii //weight: 1
        $x_1_7 = "SamIRetrieveMultiplePrimaryCredentials" ascii //weight: 1
        $x_1_8 = "CDLocateCSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Ampskerk_B_2147693078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ampskerk.B!!Ampskerk.gen!A"
        threat_id = "2147693078"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ampskerk"
        severity = "Critical"
        info = "Ampskerk: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {66 83 3a 26 75 1b 66 83 38 4b 75 15 66 83 78 0e 73 75 0e 66 83 78 1e 4b}  //weight: 5, accuracy: High
        $x_3_2 = {48 6f 6f 6b 44 43 2e 64 6c 6c 00 69 00 75 00}  //weight: 3, accuracy: High
        $x_3_3 = {48 6f 6f 6b 44 43 2e 64 6c 6c 00 69 69 00 75 75 00}  //weight: 3, accuracy: High
        $x_1_4 = "samsrv.dll" ascii //weight: 1
        $x_1_5 = "SamIRetrievePrimaryCredentials" ascii //weight: 1
        $x_1_6 = "SamIRetrieveMultiplePrimaryCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}


rule Trojan_MacOS_AMOS_HAB_2147961361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AMOS.HAB!MTB"
        threat_id = "2147961361"
        type = "Trojan"
        platform = "MacOS: "
        family = "AMOS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f be 04 08 33 85 ?? ?? ff ff 88 c1 8b 85 ?? ?? ff ff 88 8c}  //weight: 20, accuracy: Low
        $x_5_2 = "@__ZN4mlcg4prngEj" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AMOS_HAD_2147963188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AMOS.HAD!MTB"
        threat_id = "2147963188"
        type = "Trojan"
        platform = "MacOS: "
        family = "AMOS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 61 69 74 73 49 63 45 45 45 45 00 5f 5f 5a 54 43 4e 53 74 33 5f 5f 31 31 34 62 61 73 69 63 5f 6f 66 73 74 72 65 61 6d 49 63 4e 53 5f 31 31 63 68 61 72 5f 74 72 61 69 74 73 49 63 45 45 45 45 30 5f 4e 53 5f 31 33 62 61 73 69 63 5f 6f 73 74 72 65 61 6d 49 63 53 32 5f 45 45 00 5f 5f 5a 54 49 4e}  //weight: 5, accuracy: High
        $x_12_2 = {69 63 5f 6f 73 74 72 65 61 6d 49 63 53 32 5f 45 45 00 5f 5f 5a 54 49 4e 53 74 33 5f 5f 31 31 34 62 61 73 69 63 5f 6f 66 73 74 72 65 61 6d 49 63 4e 53 5f 31 31 63 68 61 72 5f 74 72 61 69 74 73 49 63 45 45 45 45 00 5f 5f 5a 54 56 4e 53 74 33 5f 5f 31 31 33 62 61 73 69 63 5f 66 69 6c 65 62 75 66 49 63 4e}  //weight: 12, accuracy: High
        $x_13_3 = {54 56 4e 53 74 33 5f 5f 31 31 33 62 61 73 69 63 5f 66 69 6c 65 62 75 66 49 63 4e 53 5f 31 31 63 68 61 72 5f 74 72 61 69 74 73 49 63 45 45 45 45 00 5f 5f 5a 54 49 4e 53 74 33 5f 5f 31 31 33 62 61 73 69 63 5f 66 69 6c 65 62 75 66 49 63 4e 53 5f 31 31 63 68 61 72 5f 74 72 61 69 74 73 49 63 45 45 45 45 00 5f 67 5f 73 65 72 69 61 6c 69 7a 65 64 5f 62 75 69 6c 64 5f 69 6e 66 6f 00 5f 5f 64 79 6c 64 5f 70 72 69 76 61 74 65}  //weight: 13, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


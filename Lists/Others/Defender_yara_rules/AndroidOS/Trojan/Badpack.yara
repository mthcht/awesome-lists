rule Trojan_AndroidOS_Badpack_A_2147892402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Badpack.A!MTB"
        threat_id = "2147892402"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Badpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {da 11 0f 08 99 04 10 11 8d 44 48 10 07 0c 97 04 04 10 8d 44 4f 04 07 0c d8 08 08 01 00 00 d8 0c 0c 01 12 04 28 df}  //weight: 2, accuracy: High
        $x_2_2 = {e2 04 03 08 e0 05 03 18 b6 54 b0 14 44 05 06 00 97 03 04 05 e0 04 01 03 e2 05 01 1d b6 54 97 01 04 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_AndroidOS_Badpack_A_2147893173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Badpack.A"
        threat_id = "2147893173"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Badpack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BFJhBFJ6QkBPQkRNTUBVSE5Pc0RQVERSVURFHARSfA" ascii //weight: 1
        $x_1_2 = "AUVETUhXRFNERQFPTlVIR0hCQFVITk9S" ascii //weight: 1
        $x_1_3 = "Bg8BZFlRREJVREUBTk9EAU5HAQY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Badpack_B_2147915261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Badpack.B!MTB"
        threat_id = "2147915261"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Badpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 40 bc 01 99 99 0a 09 35 98 0f 00 21 59 35 98 0c 00 48 09 05 08 d7 99 54 00 8d 99 4f 09 05 08 d8 08 08 01}  //weight: 1, accuracy: High
        $x_1_2 = {b7 65 38 04 0a 00 1b 07 00 01 00 00 71 10 da 01 07 00 0c 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Badpack_C_2147917135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Badpack.C!MTB"
        threat_id = "2147917135"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Badpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 00 41 14 00 00 14 01 b5 db ff ff 90 00 00 01 94 00 00 01 3d 00 1a 00 14 00 69 2c 00 00 14 01 14 f6 ff ff 91 01 00 01 90 01 00 01 94 00 01 01}  //weight: 1, accuracy: High
        $x_1_2 = {14 09 86 c5 08 00 71 30 db 00 99 09 0a 09 35 98 0f 00 21 59 35 98 0c 00 48 09 05 08 d7 99 18 00 8d 99 4f 09 05 08 d8 08 08 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Badpack_ET_2147919242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Badpack.ET"
        threat_id = "2147919242"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Badpack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "17f1afc746436f08" ascii //weight: 1
        $x_1_2 = "Lqu0da6/d3x0/it0pmx;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


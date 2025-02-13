rule Trojan_MacOS_Dakkatoni_C_2147753612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Dakkatoni.C!MTB"
        threat_id = "2147753612"
        type = "Trojan"
        platform = "MacOS: "
        family = "Dakkatoni"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com.overreach.badly" ascii //weight: 1
        $x_2_2 = {74 65 6d 70 4f 62 [0-4] 2f 6f 75 74 70 75 74 2f 73 72 63 4f 62 66 73 2f 41 75 74 [0-16] 2f 61 67 65 6e 74}  //weight: 2, accuracy: Low
        $x_1_3 = {44 89 f8 c1 f8 1f c1 e8 1c 44 01 f8 83 e0 f0 44 89 f9 29 c1 48 63 c1 8a 44 05 c0 48 8b 4d a8 42 32 04 39 88 45 bf b9 ?? 00 00 00 48 8b 7d b0 48 89 de 48 8d 55 bf 4c 8b 25 42 48 01 00 41 ff d4 49 ff c7 4c 89 ef 4c 89 f6 41 ff d4 49 39 c7 72 af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


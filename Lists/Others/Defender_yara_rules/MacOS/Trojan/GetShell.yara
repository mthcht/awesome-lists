rule Trojan_MacOS_GetShell_B_2147817366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/GetShell.B"
        threat_id = "2147817366"
        type = "Trojan"
        platform = "MacOS: "
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 5f 68 00 10 00 00 5e 6a 07 5a 68 02 10 00 00 41 5a 6a 00 41 58 6a 00 41 59 68 c5 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_GetShell_C_2147817367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/GetShell.C"
        threat_id = "2147817367"
        type = "Trojan"
        platform = "MacOS: "
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 78 1f 00 00 68 74 1f 00 00 68 6c 1f 00 00 68 53 1f 00 00 68 4f 1f 00 00 68 4b 1f 00 00 68 47 1f 00 00 68 43 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_GetShell_D_2147817368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/GetShell.D"
        threat_id = "2147817368"
        type = "Trojan"
        platform = "MacOS: "
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 78 1f 00 00 68 2a 1f 00 00 68 6e 1f 00 00 68 55 1f 00 00 68 51 1f 00 00 68 f1 1e 00 00 68 13 1f 00 00 68 3d 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_GetShell_E_2147817369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/GetShell.E"
        threat_id = "2147817369"
        type = "Trojan"
        platform = "MacOS: "
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 78 1f 00 00 68 74 1f 00 00 68 63 1e 00 00 68 9d 1e 00 00 68 e2 1e 00 00 68 f2 1e 00 00 68 ea 1e 00 00 68 ee 1e 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


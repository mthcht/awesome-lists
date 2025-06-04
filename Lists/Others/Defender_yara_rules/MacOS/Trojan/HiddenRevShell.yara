rule Trojan_MacOS_HiddenRevShell_A_2147938037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HiddenRevShell.A!MTB"
        threat_id = "2147938037"
        type = "Trojan"
        platform = "MacOS: "
        family = "HiddenRevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 80 52 21 00 80 52 02 00 80 52 d9}  //weight: 1, accuracy: High
        $x_1_2 = {e0 1f 00 b9 e1 63 00 91 e0 03 13 aa 02 02 80 52 a9}  //weight: 1, accuracy: High
        $x_2_3 = {f4 03 00 aa 01 00 80 52 61 ?? ?? ?? e0 03 14 aa 21 00 80 52 5e ?? ?? ?? e0 03 14 aa 41 00 80 52 5b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_HiddenRevShell_B_2147942769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HiddenRevShell.B!MTB"
        threat_id = "2147942769"
        type = "Trojan"
        platform = "MacOS: "
        family = "HiddenRevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 02 00 00 00 be 01 00 00 00 31 d2 e8}  //weight: 1, accuracy: High
        $x_1_2 = {89 df ba 10 00 00 00 e8}  //weight: 1, accuracy: High
        $x_2_3 = {48 89 f3 41 89 fe 31 f6 e8 ?? ?? ?? ?? 6a 01 41 5f 44 89 f7 44 89 fe e8 ?? ?? ?? ?? 6a 02 5e}  //weight: 2, accuracy: Low
        $x_2_4 = {89 df 31 f6 e8 ?? ?? ?? ?? 89 df be 01 00 00 00 e8 c7 01 00 00 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


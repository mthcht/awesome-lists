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


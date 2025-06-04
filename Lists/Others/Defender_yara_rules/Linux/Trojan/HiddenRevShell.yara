rule Trojan_Linux_HiddenRevShell_A_2147936335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/HiddenRevShell.A!MTB"
        threat_id = "2147936335"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "HiddenRevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 cc 48 8d 4d d0 8b 45 cc ba 10 00 00 00 48 89 ce 89 c7 e8}  //weight: 2, accuracy: High
        $x_2_2 = {48 89 45 e0 48 c7 45 e8 00 00 00 00 48 8d 45 e0 ba 00 00 00 00 48 89 c6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_HiddenRevShell_B_2147942815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/HiddenRevShell.B!MTB"
        threat_id = "2147942815"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "HiddenRevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 f6 89 df e8 ?? ?? ?? ?? be 01 00 00 00 89 df e8 ?? ?? ?? ?? be 02 00 00 00 89 df e8}  //weight: 2, accuracy: Low
        $x_1_2 = {48 89 e6 ba 10 00 00 00 89 df 89 44 24 04 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Linux_ShellAgnt_A_2147797301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShellAgnt.A!MTB"
        threat_id = "2147797301"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShellAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 89 e8 ff d0 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 6a 0a 68 0a 00 02 61}  //weight: 1, accuracy: High
        $x_1_2 = {68 0a 00 02 61 68 02 00 1a 0a 89 e6 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 0a ff 4e 08 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


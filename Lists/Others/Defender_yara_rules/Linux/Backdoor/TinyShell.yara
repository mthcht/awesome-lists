rule Backdoor_Linux_TinyShell_A_2147945641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/TinyShell.A!MTB"
        threat_id = "2147945641"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "TinyShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 f8 8b 4d 08 01 c1 8b 45 f8 8b 55 08 01 c2 8a 45 ff 32 02 88 01 8d 45 f8 ff 00}  //weight: 2, accuracy: High
        $x_1_2 = "icmp[4:2] == 0xaa56" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_Conpee_A_2147655026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Conpee.A"
        threat_id = "2147655026"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Conpee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PeerConn^_^Me2" ascii //weight: 1
        $x_1_2 = {6d 73 70 61 74 63 68 2e 64 6c 6c 00 77 75 61 75 73 65 72 76}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 08 03 55 fc 0f be 02 83 e8 ?? 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f be 02 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Conpee_A_2147655027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Conpee.A"
        threat_id = "2147655027"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Conpee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 65 65 72 5f 70 6c 75 67 69 6e 5f (6d 61|63 6f 6d 6d 61) 00}  //weight: 1, accuracy: Low
        $x_1_2 = "<remotefile> <localfile>" ascii //weight: 1
        $x_1_3 = "PlugMgr_RegisterCommand" ascii //weight: 1
        $x_1_4 = "iisgetdir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Conpee_A_2147655027_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Conpee.A"
        threat_id = "2147655027"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Conpee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00 00 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "iisput" ascii //weight: 1
        $x_1_3 = "iisget" ascii //weight: 1
        $x_1_4 = "peer_plugin_main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


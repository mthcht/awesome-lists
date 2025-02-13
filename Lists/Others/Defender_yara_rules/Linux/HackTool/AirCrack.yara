rule HackTool_Linux_AirCrack_A_2147762154_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/AirCrack.A!MTB"
        threat_id = "2147762154"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "AirCrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aircrack-ng" ascii //weight: 1
        $x_1_2 = "lib/ce-wep/uniqueiv.c" ascii //weight: 1
        $x_1_3 = "wep-decloak" ascii //weight: 1
        $x_1_4 = "PTW_newattackstate()" ascii //weight: 1
        $x_1_5 = "ptw-debug" ascii //weight: 1
        $x_1_6 = "aircrack-ce-wpa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_AirCrack_A_2147762154_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/AirCrack.A!MTB"
        threat_id = "2147762154"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "AirCrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "minimum required for a dictionary attack" ascii //weight: 1
        $x_1_2 = {70 6f 72 74 73 2f 61 69 72 63 72 61 63 6b 2d 6e 67 [0-6] 2f 61 69 72 63 72 61 63 6b 2d 6e 67 [0-6] 2f 73 72 63 2f 61 69 72 63 72 61 63 6b 2d 63 72 79 70 74 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "disable  bruteforce   multithreading" ascii //weight: 1
        $x_1_4 = "PTW_newattackstate" ascii //weight: 1
        $x_1_5 = "Attack will be restarted every %d captured ivs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_AirCrack_B_2147807679_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/AirCrack.B!MTB"
        threat_id = "2147807679"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "AirCrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 e8 01 0f 85 87 fe ff ff 48 8d ?? ?? ?? 01 00 e8 5d cc ff ff 48 8b ?? ?? ?? 0b 00 e8 ?? ?? ?? ?? 4c 89 ea 4c 89 e6 48 89 c5 48 89 c7 e8 ?? ?? ?? 00 48 89 ef e8 ?? ?? ?? 00 48 8b 54 24 50 4c 8d ?? ?? ?? 01 00 41 b8 ?? ?? 00 00 48 85 d2 0f 84 ?? ?? ?? ff 48 8b ?? ?? ?? 0b 00 48 8d b2 00 01 00 00 c7 82 68 01 00 00 01 00 00 00 e8 ?? ?? ?? 00 e9 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {41 b8 01 00 00 00 4c 89 f1 4c 89 ea 48 89 ee e8 ?? ?? ?? 00 85 c0 74 ?? 48 8b bb 08 03 00 00 48 83 83 50 01 00 00 01 48 85 ff 75 ?? e8 62 ?? ?? ?? 48 89 83 08 03 00 00 48 89 c7 48 85 c0 0f 85 ?? ?? ?? ff 48 8d ?? ?? ?? ?? 00 e8 ?? ?? ?? ff e9 ?? ?? ?? ff 66 0f 1f 44 00 00 e8 ?? ?? ?? 00 48 89 83 00 03 00 00 48 89 c7 48 85 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


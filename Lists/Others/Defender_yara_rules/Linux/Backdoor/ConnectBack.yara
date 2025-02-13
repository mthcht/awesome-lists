rule Backdoor_Linux_ConnectBack_A_2147794759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/ConnectBack.A!xp"
        threat_id = "2147794759"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "ConnectBack"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b9 02 00 ?? ?? ?? ?? ?? ?? 51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 59 48 85 c0 79 25 49 ff c9 74 18 57 6a 23 58 6a 00 6a 05 48 89 e7 48 31 f6 0f 05 59 59 5f 48 85 c0 79 c7 6a 3c 58 6a 01 5f 0f 05 5e 6a 7e 5a 0f 05 48 85 c0 78 ed ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_ConnectBack_B_2147819340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/ConnectBack.B!MTB"
        threat_id = "2147819340"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "ConnectBack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


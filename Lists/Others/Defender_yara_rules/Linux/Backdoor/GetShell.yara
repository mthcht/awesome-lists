rule Backdoor_Linux_GetShell_A_2147658604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GetShell.A"
        threat_id = "2147658604"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 66 58 89 e1 cd 80 97 5b 68 [0-8] 66 68 1f 91 66 53 89 e1 6a 66}  //weight: 1, accuracy: Low
        $x_1_2 = {89 e1 43 cd 80 5b 99 b6 0c b0 03 cd 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_GetShell_A_2147797444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GetShell.A!xp"
        threat_id = "2147797444"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 48 97 48 b9 02 00 ?? ?? ?? ?? ?? ?? 51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 6a 03 5e 48 ff ce 6a 21 58 0f 05 75 f6 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 48 89 e7 52 57 48 89 e6 0f 05}  //weight: 1, accuracy: Low
        $x_1_2 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 b2 07 b9 00 10 00 00 89 e3 c1 eb 0c c1 e3 0c b0 7d cd 80 5b 89 e1 99 b6 0c b0 03 cd 80 ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_GetShell_B_2147797447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GetShell.B!xp"
        threat_id = "2147797447"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 53 43 53 6a 0a 89 e1 6a 66 58 cd 80 96 99 52 52 52 52 52 52 66 68 ?? ?? 66 68 0a 00 89 e1 6a 1c 51 56 89 e1 43 6a 66 58 cd 80 b0 66 b3 04 cd 80 52 52 56 89 e1 43 b0 66 cd 80 93 59}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 3f 58 cd 80 49 79 f8 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 b0 0b cd 80}  //weight: 1, accuracy: High
        $x_1_3 = {31 db f7 e3 53 43 53 6a 02 89 e1 b0 66 cd 80 93 59 b0 3f cd 80 49 79 f9 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e1 b0 66}  //weight: 1, accuracy: Low
        $x_1_4 = {50 51 53 b3 03 89 e1 cd 80 52 68 6e 2f 73 68 68 2f 2f 62 69 89 e3 52 53 89 e1 b0 0b cd 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_GetShell_B_2147819332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GetShell.B!MTB"
        threat_id = "2147819332"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 7f 00 00 01 68 02 00 15 b3 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 ?? 4e 74 ?? 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {cd 80 93 59 b0 3f cd 80 49 79 ?? 68 c0 a8 01 4e 68 02 00 10 e1 89 e1 b0 66 50 51 53 b3 03 89 e1 cd 80 52 ba 00 00 73 68 66 ba 6e 2f 52 ba 00 00 62 69 66 ba 2f 2f 52 31 d2 89 e3 52 53 89 e1 b0 0b cd 80}  //weight: 1, accuracy: Low
        $x_1_3 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 2e 69 79 44 68 02 00 da c2 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd}  //weight: 1, accuracy: High
        $x_1_4 = {6a 0a 5e 31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 a4 5c dd 9e 68 02 00 11 5c 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27 b2 07 b9 00 10 00 00 89 e3 c1 eb 0c c1 e3 0c b0 7d cd 80 85 c0 78 10 5b 89 e1 99 b2 6a b0 03 cd 80 85 c0 78 02 ff e1 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_GetShell_C_2147835607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GetShell.C!MTB"
        threat_id = "2147835607"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00 00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08 00 80 04 08 ea 00 00 00 80 01 00 00 07 00 00 00 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_GetShell_I_2147890018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GetShell.I!MTB"
        threat_id = "2147890018"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_GetShell_K_2147893551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/GetShell.K!MTB"
        threat_id = "2147893551"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "GetShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 04 08 00 80 04 08 56 01 00 00 58 02 00 00 07 00 00 00 00 10 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


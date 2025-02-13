rule Trojan_O97M_Mraitlce_D_2147773070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Mraitlce.D!MTB"
        threat_id = "2147773070"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Mraitlce"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 6f 72 20 63 6f 75 6e 74 65 72 20 3d 20 4c 42 6f 75 6e 64 28 [0-8] 29 20 54 6f 20 55 42 6f 75 6e 64 28 [0-32] 20 3d 20 62 75 66 28 [0-32] 20 3d 20 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 28 [0-16] 20 2b 20 63 6f 75 6e 74 65 72 2c 20 [0-8] 2c 20 31 29 [0-8] 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 54 68 72 65 61 64 28 30 2c 20 30 2c 20 [0-8] 2c 20 30 2c 20 30 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 30 2c 20 55 42 6f 75 6e 64 28 [0-8] 29 2c 20 26 48 33 30 30 30 2c 20 26 48 34 30 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Mraitlce_A_2147773618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Mraitlce.A!MTB"
        threat_id = "2147773618"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Mraitlce"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"C:\\Users\\\" & GetUserName & \"\\AppData\\Roaming\\" ascii //weight: 1
        $x_3_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 [0-16] 2c 20 [0-16] 20 26 20 22 [0-16] 2e 62 61 74 22 2c 20 30 2c 20 30}  //weight: 3, accuracy: Low
        $x_1_3 = "Shell (\"C:\\Users\\\" & GetUserName & \"\\AppData\\Roaming\\article.txt\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Mraitlce_B_2147773619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Mraitlce.B!MTB"
        threat_id = "2147773619"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Mraitlce"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 54 54 50 44 6f 77 6e 6c 6f 61 64 20 27 68 74 74 70 3a 2f 2f [0-48] 2e 65 78 65 27 2c 20 27 43 3a 5c 74 65 6d 70 27}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 63 3a 5c 74 65 6d 70 5c [0-8] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_3 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 27 63 3a 5c 74 65 6d 70 5c [0-8] 2e 65 78 65 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


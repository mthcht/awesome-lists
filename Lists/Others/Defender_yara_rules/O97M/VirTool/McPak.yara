rule VirTool_O97M_McPak_B_2147812175_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:O97M/McPak.B!MTB"
        threat_id = "2147812175"
        type = "VirTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "McPak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-37] 28 22 35 37 [0-37] 35 33 [0-37] 36 33 [0-37] 37 32 [0-37] 36 39 [0-37] 37 30 [0-37] 37 34 [0-37] 32 65 [0-37] 35 33 [0-37] 36 38 [0-37] 36 35 [0-37] 36 63 [0-37] 36 63 22 29 29 2e 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 76 69 72 6f 6e 28 22 43 4f 4d 50 55 54 45 52 4e 41 4d 45 [0-48] 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 44 4f 4d 41 49 4e}  //weight: 1, accuracy: Low
        $x_1_3 = {50 61 72 65 6e 74 57 69 6e 64 6f 77 2e 43 6c 69 70 62 6f 61 72 64 44 61 74 61 2e 47 65 74 44 61 74 61 28 [0-32] 37 34 [0-32] 36 35 [0-32] 37 38 [0-32] 37 34}  //weight: 1, accuracy: Low
        $x_1_4 = {36 39 36 34 33 64 [0-53] 32 36 [0-32] 36 33 [0-32] 36 64 [0-32] 36 34 [0-32] 34 66 [0-32] 37 35 [0-32] 37 34 [0-32] 37 30 [0-32] 37 35 [0-32] 37 34 [0-32] 33 64}  //weight: 1, accuracy: Low
        $x_1_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 22 35 37 [0-32] 36 39 [0-32] 36 65 [0-32] 34 38 [0-32] 37 34 [0-32] 37 34 [0-32] 37 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_O97M_McPak_F_2147812176_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:O97M/McPak.F!MTB"
        threat_id = "2147812176"
        type = "VirTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "McPak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 20 22 37 37 [0-5] 39 30 [0-5] 31 34 34}  //weight: 1, accuracy: Low
        $x_1_2 = "Environ(\"AppData\")" ascii //weight: 1
        $x_1_3 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 [0-16] 53 75 62 [0-32] 2e 61 73 64}  //weight: 1, accuracy: Low
        $x_1_4 = "Scripting.FileSystemObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_O97M_McPak_F_2147812176_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:O97M/McPak.F!MTB"
        threat_id = "2147812176"
        type = "VirTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "McPak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 [0-16] 26}  //weight: 1, accuracy: Low
        $x_1_2 = {4f 70 65 6e 54 65 78 74 46 69 6c 65 28 [0-16] 2c 20 32 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 [0-32] 53 75 62 [0-32] 4c 69 62}  //weight: 1, accuracy: Low
        $x_1_4 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-32] 2c 20 [0-32] 2c 20 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_O97M_McPak_E_2147812177_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:O97M/McPak.E!MTB"
        threat_id = "2147812177"
        type = "VirTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "McPak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 61 76 65 54 6f 46 69 6c 65 [0-117] 32}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 [0-16] 53 75 62 [0-32] 2e 61 73 64}  //weight: 1, accuracy: Low
        $x_1_3 = "Environ(\"AppData\")" ascii //weight: 1
        $x_1_4 = "MSXML2.ServerXMLHTTP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_O97M_McPak_E_2147812177_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:O97M/McPak.E!MTB"
        threat_id = "2147812177"
        type = "VirTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "McPak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 34 31 [0-32] 34 34 [0-32] 34 66 [0-32] 34 34 [0-32] 34 32 [0-32] 32 65 [0-32] 35 33 [0-32] 37 34 [0-32] 37 32 [0-32] 36 35 [0-32] 36 31 [0-32] 36 64}  //weight: 1, accuracy: Low
        $x_1_2 = {53 61 76 65 54 6f 46 69 6c 65 [0-117] 32}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 [0-16] 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-32] 2c [0-32] 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


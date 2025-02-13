rule Trojan_O97M_MalDoc_RM_2147761353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/MalDoc.RM!MTB"
        threat_id = "2147761353"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MalDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 72 65 61 74 65 28 22 72 75 6e 64 6c 6c 33 32 20 22 20 2b 20 [0-31] 20 26 20 22 2e 44 4c 4c 2c 53 74 61 72 74 57 22 2c}  //weight: 1, accuracy: Low
        $x_1_2 = ".create(\"rundll32 ntlanui.dll,ShareCreate" ascii //weight: 1
        $x_1_3 = {2e 63 72 65 61 74 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 20 2b 20 [0-15] 20 2b 20 22 2e 64 6f 63 20 22 20 2b 20 00 20 2b 20 22 2e 44 4c 4c 22 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 43 3a 5c 41 55 47 55 53 54 (30|2d|39) (30|2d|39) 22 0d 0a [0-47] 44 6f 63 75 6d 65 6e 74 5f 46 41 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_MalDoc_AJK_2147772611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/MalDoc.AJK!MSR"
        threat_id = "2147772611"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MalDoc"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "184zzz.164zzz.146zzz.102" ascii //weight: 1
        $x_1_2 = "Split(merenge, \"zzz\")" ascii //weight: 1
        $x_1_3 = "cmd kkk/C kkkexekkkfingerkkk%appdata%" ascii //weight: 1
        $x_1_4 = "certutilooo -decode" ascii //weight: 1
        $x_1_5 = "Split(arena, \"ooo\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


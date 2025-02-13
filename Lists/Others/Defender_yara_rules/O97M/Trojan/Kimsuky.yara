rule Trojan_O97M_Kimsuky_2147751893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Kimsuky!MSR"
        threat_id = "2147751893"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kimsuky"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 6e 6f 4c 6f 67 6f 20 24 73 3d 5b 53 79 73 74 65 6d 2e 49 4f 2e 46 69 6c 65 5d 3a 3a 52 65 61 64 41 6c 6c 54 65 78 74 28 27 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-10] 2e 74 78 74 27 29 3b 69 65 78 20 24 73}  //weight: 1, accuracy: Low
        $x_1_2 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = ".Run d1, Left" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


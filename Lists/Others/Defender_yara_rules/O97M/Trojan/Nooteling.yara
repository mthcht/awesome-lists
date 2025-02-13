rule Trojan_O97M_Nooteling_B_2147757770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Nooteling.B!dha"
        threat_id = "2147757770"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Nooteling"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 65 63 73 74 61 67 65 5f ?? 20 3d 20 62 36 34 44 65 63 6f 64 65 28 73 74 61 67 65 5f ?? 29}  //weight: 1, accuracy: Low
        $x_1_2 = "stage_2 = \"AAEAAAD/////" ascii //weight: 1
        $x_1_3 = "Function b64Decode(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Nooteling_A_2147757984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Nooteling.A!dha"
        threat_id = "2147757984"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Nooteling"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"504b030414" ascii //weight: 1
        $x_1_2 = "Function WriteBin(filename, BufferData)" ascii //weight: 1
        $x_1_3 = "\\Microsoft\\Word\\STARTUP\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


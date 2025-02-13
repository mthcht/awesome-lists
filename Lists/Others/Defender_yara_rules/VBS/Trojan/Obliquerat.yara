rule Trojan_VBS_Obliquerat_2147751392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBS/Obliquerat!MTB"
        threat_id = "2147751392"
        type = "Trojan"
        platform = "VBS: Visual Basic scripts"
        family = "Obliquerat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "file_Salan_name = \"sgrmbrokr\"" ascii //weight: 1
        $x_1_2 = "zip_Salan_file = fldr_Salan_name & file_Salan_name & \".doc\"" ascii //weight: 1
        $x_1_3 = {4e 61 6d 65 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-9] 2e 64 6f 63 22 20 41 73 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-9] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c [0-6] 2e 75 72 6c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


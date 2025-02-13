rule Virus_Linux_Amalthea_A_2147650205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Linux/Amalthea.A"
        threat_id = "2147650205"
        type = "Virus"
        platform = "Linux: Linux platform"
        family = "Amalthea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 2e 63 00 2e 43 00 69 6e 69 74 5f 68 61 73 68 00 0a 6d 61 69 6e 28 00 0a 69 6e 74 20 6d 61 69 6e 28 00}  //weight: 1, accuracy: High
        $x_1_2 = {3b 0a 09 63 68 61 72 20 68 61 73 68 62 65 67 5b 5d 20 3d 20 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {3b 0a 09 63 68 61 72 20 68 61 73 68 65 6e 64 5b 5d 20 3d 20 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Linux_Amalthea_B_2147650468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Linux/Amalthea.B"
        threat_id = "2147650468"
        type = "Virus"
        platform = "Linux: Linux platform"
        family = "Amalthea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 2e 63 00 2e 43 00 69 6e 69 74 5f 68 61 73 68 00 0a 6d 61 69 6e 28 00 0a 69 6e 74 20 6d 61 69 6e 28 00}  //weight: 1, accuracy: High
        $x_1_2 = ";\\n\\tchar hashbeg[] =\\\"\"" ascii //weight: 1
        $x_1_3 = ";\\n\\tchar hashend[] =\\\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


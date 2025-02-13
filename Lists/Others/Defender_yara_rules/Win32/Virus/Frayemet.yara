rule Virus_Win32_Frayemet_A_2147649550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Frayemet.gen!A"
        threat_id = "2147649550"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Frayemet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4d 79 46 69 6c 65 28 40 6d 79 5f 61 72 72 61 79 2c 73 69 7a 65 6f 66 28 6d 79 5f 61 72 72 61 79 29 2c 27 7e 2e 65 78 65 27 29 3b 0d 0a 00 7b 24 49 46 44 45 46 20 4d 53 57 49 4e 44 4f 57 53 7d 0d 0a 70 72 6f 63 65 64 75 72 65 20 5f 49 6e 69 74 45 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "SysInit.pas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


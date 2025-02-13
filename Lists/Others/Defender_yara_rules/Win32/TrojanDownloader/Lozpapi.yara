rule TrojanDownloader_Win32_Lozpapi_A_2147648610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lozpapi.A"
        threat_id = "2147648610"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lozpapi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 72 6f 62 61 74 55 70 64 61 74 65 72 00 ?? 41 64 6f 62 65 20 41 63 72 6f 62 61 74 20 55 70 64 61 74 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = {43 42 72 6f 77 73 65 72 52 48 65 61 64 65 72 00 41 63 72 6f 62 61 74 55 70 64 61 74 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "%218up-Y%1A.%25%09%17.QDL%25%05%1F" wide //weight: 1
        $x_1_4 = "%3B%02Cu%15%1FDD=-=%09FEQ%12%0E%1AVAPF%1FfBZ" wide //weight: 1
        $x_1_5 = {6d 00 65 00 74 00 61 00 20 00 00 00 00 00 0e 00 00 00 72 00 65 00 66 00 72 00 65 00 73 00 68 00 00 00 08 00 00 00 75 00 72 00 6c 00 3d}  //weight: 1, accuracy: High
        $x_1_6 = {48 00 45 00 41 00 44 00 00 00 00 00 02 00 00 00 30 00 00 00 08 00 00 00 67 00 7a 00 69 00 70 00 00 00 00 00 0e 00 00 00 64 00 65 00 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Lozpapi_B_2147657804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lozpapi.B"
        threat_id = "2147657804"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lozpapi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Slk-=ak4jjDSA21!@kk#$#21" wide //weight: 1
        $x_1_2 = "%218up-Y%1A.%25%09%17.QDL%25%05%1F" wide //weight: 1
        $x_1_3 = "%3B%02Cu%15%1FDD=-=%09FEQ%12%0E%1AVAPF%1FfBZ" wide //weight: 1
        $x_1_4 = {6d 00 65 00 74 00 61 00 20 00 00 00 00 00 0e 00 00 00 72 00 65 00 66 00 72 00 65 00 73 00 68 00 00 00 08 00 00 00 75 00 72 00 6c 00 3d}  //weight: 1, accuracy: High
        $x_1_5 = {48 00 45 00 41 00 44 00 00 00 00 00 02 00 00 00 30 00 00 00 08 00 00 00 67 00 7a 00 69 00 70 00 00 00 00 00 0e 00 00 00 64 00 65 00 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


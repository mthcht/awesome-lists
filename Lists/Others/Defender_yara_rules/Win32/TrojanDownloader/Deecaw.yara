rule TrojanDownloader_Win32_Deecaw_A_2147598381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deecaw.A"
        threat_id = "2147598381"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deecaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 70 68 70 00 55 73 65 72 44 61 74 61}  //weight: 2, accuracy: High
        $x_1_2 = "/icount." ascii //weight: 1
        $x_2_3 = "uid=%s&pcodes=%s" ascii //weight: 2
        $x_2_4 = {75 69 64 3d 25 73 00 00 50 4f 53 54}  //weight: 2, accuracy: High
        $x_1_5 = "AppInit_DLLs" ascii //weight: 1
        $x_2_6 = {5f 64 6f 77 6e 6c 6f 61 64 00 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_7 = "ldcore_" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Caftuli_A_2147649764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Caftuli.A"
        threat_id = "2147649764"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Caftuli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 00 6f 00 67 00 2f 00 70 00 6c 00 61 00 79 00 2e 00 70 00 68 00 70 00 3f 00 68 00 6f 00 73 00 74 00 3d 00 [0-18] 26 00 6d 00 61 00 63 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "gmHTTP_REQUEST" wide //weight: 1
        $x_1_3 = "date/update.xml" wide //weight: 1
        $x_1_4 = "gmGET_MACADDRESS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


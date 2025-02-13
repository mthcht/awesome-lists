rule PWS_Win32_Serkdes_A_2147679668_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Serkdes.A"
        threat_id = "2147679668"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Serkdes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-[ Virtual Shell]-" wide //weight: 1
        $x_1_2 = "Not Comming From Our Server" wide //weight: 1
        $x_1_3 = {00 50 75 74 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_4 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii //weight: 1
        $x_1_5 = {35 65 37 65 38 31 30 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


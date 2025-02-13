rule PWS_Win32_Nabrek_A_2147697459_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Nabrek.A"
        threat_id = "2147697459"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nabrek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 68 69 74 65 55 52 4c 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 79 4b 42 00}  //weight: 1, accuracy: High
        $x_1_3 = "DG8FV-B9TKY-FRT9J-6CRCC-XPQ4G-" ascii //weight: 1
        $x_1_4 = "/tongji.html" ascii //weight: 1
        $x_1_5 = "/step/main.php" ascii //weight: 1
        $x_1_6 = "/mybank.php" ascii //weight: 1
        $x_1_7 = ":9000/ipr.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


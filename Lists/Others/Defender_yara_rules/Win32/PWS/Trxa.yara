rule PWS_Win32_Trxa_A_2147684737_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Trxa.A"
        threat_id = "2147684737"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Trxa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 71 3d 61 74 72 61 78 73 74 65 61 6c 65 72}  //weight: 1, accuracy: High
        $x_1_2 = "Atrax Stealer" ascii //weight: 1
        $x_1_3 = {8a 07 3c 2d 74 36 3c 5f 74 32 3c 2e 74 2e 3c 7e 74 2a 3c 20 75 05 c6 06 2b eb 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


rule Backdoor_Win32_Lerif_A_2147682510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lerif.A"
        threat_id = "2147682510"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lerif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 65 00 67 00 77 00 72 00 69 00 74 00 65 00 [0-10] 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 [0-10] 5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 [0-10] 6f 00 70 00 65 00 6e 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Status: [ UDP - Attack Enabled ]" wide //weight: 1
        $x_1_3 = {50 00 6c 00 7a 00 46 00 72 00 7a 00 [0-10] 46 00 55 00 43 00 4b 00 59 00 4f 00 55 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


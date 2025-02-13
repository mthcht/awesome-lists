rule PWS_Win32_Lersta_A_2147705972_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lersta.A"
        threat_id = "2147705972"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lersta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3f 09 74 19 80 3f 0d 74 14 80 3f 0a 74 0f 80 3f 5b 74 0a 80 3f 5d 74 05 80 3f 60 75 03 c6 07 20 47 80 3f 00 75 d9}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Far2\\SavedDialogHistory\\FTPHost" wide //weight: 1
        $x_1_3 = "\\VanDyke\\Config\\Sessions" wide //weight: 1
        $x_1_4 = "stealer.done" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


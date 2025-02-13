rule PWS_Win32_Scofted_2147608172_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Scofted"
        threat_id = "2147608172"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Scofted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 70 77 66 69 6c 65 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 6c 6f 67 65 6e 63 72 79 70 74 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_2_3 = "Codesoft PW Stealer" ascii //weight: 2
        $x_1_4 = "FTP Password Stealer" ascii //weight: 1
        $x_1_5 = "FlashFXP Userdaten:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


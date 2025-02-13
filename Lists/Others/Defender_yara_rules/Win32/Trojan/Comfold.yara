rule Trojan_Win32_Comfold_A_2147658640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Comfold.A"
        threat_id = "2147658640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Comfold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "comhorse.dat" ascii //weight: 1
        $x_1_2 = "\\UserUDiskID.dat" ascii //weight: 1
        $x_1_3 = "%sRECYCLER\\S" ascii //weight: 1
        $x_1_4 = {5c 72 65 6d 6f 74 65 2e (62|64) 61 74}  //weight: 1, accuracy: Low
        $x_1_5 = "\\msrss.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


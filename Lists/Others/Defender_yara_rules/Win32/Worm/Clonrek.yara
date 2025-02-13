rule Worm_Win32_Clonrek_A_2147684362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Clonrek.A"
        threat_id = "2147684362"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Clonrek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MP\\vxjtg.exe autorunned" ascii //weight: 1
        $x_1_2 = "rghost.ru/download/42876583" ascii //weight: 1
        $x_1_3 = "poclbm120823GeForce 9600 GTv1w256l4.bin" ascii //weight: 1
        $x_1_4 = {43 4c 43 4b 00 00 00 00 4d 69 6e 69 6e 67 20 73 74 61 72 74 65 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


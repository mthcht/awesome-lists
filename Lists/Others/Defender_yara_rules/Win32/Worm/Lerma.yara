rule Worm_Win32_Lerma_A_2147600242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lerma.A"
        threat_id = "2147600242"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lerma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ModErma" ascii //weight: 1
        $x_1_2 = "LASeRMa" wide //weight: 1
        $x_1_3 = "~~-<<-=Cecacing Hari Kiamat Menjelang Tiba Insaflah Insan By Lasiaf=->>-~~" wide //weight: 1
        $x_1_4 = "Mypicture.exe" wide //weight: 1
        $x_1_5 = "drivetype" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


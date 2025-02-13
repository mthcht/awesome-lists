rule Worm_Win32_Barten_A_2147601141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Barten.A"
        threat_id = "2147601141"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Barten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smtp.terra.com.br;vac" ascii //weight: 1
        $x_1_2 = "smtp.terra.com.br;barata" ascii //weight: 1
        $x_1_3 = "consensual.%" ascii //weight: 1
        $x_1_4 = "lstrepetidos" ascii //weight: 1
        $x_1_5 = "<title>Menina" ascii //weight: 1
        $x_1_6 = "__zbSessionTMP/video.php" ascii //weight: 1
        $x_1_7 = "Messenger\\msmsgs.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


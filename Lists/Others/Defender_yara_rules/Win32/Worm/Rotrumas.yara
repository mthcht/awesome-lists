rule Worm_Win32_Rotrumas_A_2147608370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rotrumas.A"
        threat_id = "2147608370"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotrumas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\26.04.2007\\BAd Proj\\VIR\\Penetrator\\JB15\\Project1.vbp" wide //weight: 1
        $x_1_2 = " http://softclub.land.ru/seeing/katie.rar" wide //weight: 1
        $x_1_3 = "MY ICQ: 402974020" wide //weight: 1
        $x_1_4 = "ot02_88@mail.ru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


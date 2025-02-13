rule Trojan_Win32_Nibagem_A_2147696122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nibagem.A"
        threat_id = "2147696122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nibagem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 13 8b 55 a8 3b 55 e8 77 0b 8b 45 a8 89 45 ac e9 b8 00 00 00 8b 4d a8 3b 4d e8 0f}  //weight: 1, accuracy: High
        $x_1_2 = "dpaste.dzfl.pl" ascii //weight: 1
        $x_1_3 = "/raw/c5365422c287" ascii //weight: 1
        $x_1_4 = "/images/xml.php?v=DxCvHjQzaEBVCX&id=" ascii //weight: 1
        $x_1_5 = "megabinx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


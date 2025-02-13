rule Worm_Win32_Scafros_A_2147638371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Scafros.A"
        threat_id = "2147638371"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Scafros"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "azadunimsh/ip.txt" ascii //weight: 1
        $x_1_2 = "#startkeylog" ascii //weight: 1
        $x_1_3 = "#blackchat" ascii //weight: 1
        $x_1_4 = "#photosend" ascii //weight: 1
        $x_1_5 = "#yahoousrpwd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


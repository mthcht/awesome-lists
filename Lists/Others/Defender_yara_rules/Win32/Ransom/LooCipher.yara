rule Ransom_Win32_LooCipher_PI_2147741625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LooCipher.PI"
        threat_id = "2147741625"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LooCipher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\@LooCipher_wallpaper.bmp" ascii //weight: 1
        $x_1_2 = "\\Desktop\\@Please_Read_Me.txt" ascii //weight: 1
        $x_1_3 = "\\Desktop\\c2056.ini" ascii //weight: 1
        $x_1_4 = "LooCipher" wide //weight: 1
        $x_1_5 = "\\LooCipher.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


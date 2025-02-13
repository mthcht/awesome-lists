rule Ransom_Win32_WastMario_PA_2147757795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WastMario.PA!MTB"
        threat_id = "2147757795"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WastMario"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5c 55 73 65 72 73 5c 72 6f 69 6c 65 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 57 61 73 74 65 64 42 69 74 5c [0-16] 5c 57 61 73 74 65 64 42 69 74 2e 70 64 62}  //weight: 4, accuracy: Low
        $x_2_2 = "\\Documents\\WastedBit\\Wasted.bmp" ascii //weight: 2
        $x_2_3 = "You'r files has been locked by Mario" ascii //weight: 2
        $x_2_4 = "\\Documents\\WastedBit\\mario.wav" ascii //weight: 2
        $x_2_5 = "srv-file7.gofile.io/download/6MAQQl/Mario-PixTeller.png" ascii //weight: 2
        $x_1_6 = "@Readme.txt" ascii //weight: 1
        $x_1_7 = ".wasted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Cryptnot_LR_2147972616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptnot.LR!MTB"
        threat_id = "2147972616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptnot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b cb 8b 5d fc 2b c8 8b 45 dc 0f b7 04 83 0f af c8 8b 45 dc 01 8e 2c af 01 00 8b 4d d4 66 89 4c 83 02 8b 5d f8}  //weight: 20, accuracy: High
        $x_1_2 = "_Screen_Desktop.jpeg" ascii //weight: 1
        $x_2_3 = "filename=\"%lu.zip\"" ascii //weight: 2
        $x_3_4 = "boundary=---------------------------%lu" ascii //weight: 3
        $x_4_5 = "AutoIt_New.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


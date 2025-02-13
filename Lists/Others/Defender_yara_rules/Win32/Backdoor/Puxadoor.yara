rule Backdoor_Win32_Puxadoor_A_2147646229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Puxadoor.A"
        threat_id = "2147646229"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Puxadoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "puxasistema" wide //weight: 1
        $x_1_2 = "puxador" ascii //weight: 1
        $x_2_3 = "VerificarAplicativo" ascii //weight: 2
        $x_2_4 = {8b 75 10 8d 45 dc 8b 16 52 50 ff d7 8b 5d 0c}  //weight: 2, accuracy: High
        $x_2_5 = {be 08 00 00 00 83 c4 0c 8d 95 54 fd ff ff 8d 8d 84 fd ff ff c7 85 5c fd ff ff ?? ?? ?? 00 89 b5 54 fd ff ff ff 15 ?? ?? ?? 00 8d 85 84 fd ff ff 8d 8d 74 fd ff ff 50 51 ff 15 ?? ?? ?? 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


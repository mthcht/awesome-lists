rule TrojanDropper_Win32_Mafchek_A_2147637590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Mafchek.A"
        threat_id = "2147637590"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Mafchek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff b5 78 ff ff ff ff b5 7c ff ff ff 8d 45 80 50 e8 18 01 00 00 68 ?? ?? ?? ?? 8d 45 80 50 e8 45 00 00 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


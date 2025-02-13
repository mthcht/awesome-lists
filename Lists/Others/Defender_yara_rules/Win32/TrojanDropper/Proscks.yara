rule TrojanDropper_Win32_Proscks_C_2147618051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Proscks.C"
        threat_id = "2147618051"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Proscks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 01 00 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff e8 01 02 03 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff e8 01 02 03 ff 15 ?? ?? 40 00 e8 ?? ?? ff ff e8 01 02 03 e8 0c 00 00 00 74 61 73 6b 6d 67 72 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


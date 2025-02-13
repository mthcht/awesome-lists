rule TrojanDropper_Win32_Rooter_A_2147610447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rooter.A"
        threat_id = "2147610447"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rooter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 db 75 0b 6a 01 e8 ?? ?? ?? ?? 84 db 74 f5 (b8|2d|bb) ?? ?? ?? ?? (b8|2d|bb) ?? ?? ?? ?? 8a [0-5] 32 [0-5] 32 [0-5] 88 [0-5] 80 fb ff 75 04 b3 01 eb 01 ?? (40|2d|4f) (40|2d|4f) 75 ?? 8d 45 ec ba ?? ?? ?? ?? b9 00 01 00 00 e8 ?? ?? ff ff 8d 45 ec 8b 15 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 55 ec b8 ?? ?? ?? ?? e8 ?? ?? ff ff ba 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


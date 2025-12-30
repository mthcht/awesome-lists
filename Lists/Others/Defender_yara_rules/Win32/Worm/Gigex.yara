rule Worm_Win32_Gigex_AGI_2147960230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gigex.AGI!MTB"
        threat_id = "2147960230"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gigex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 04 01 00 00 ff 35 b8 5b 40 00 e8 ?? ?? ?? ?? 68 04 01 00 00 ff 35 84 5b 40 00 e8 ?? ?? ?? ?? 68 04 01 00 00 ff 35 c0 5b 40 00 e8 ?? ?? ?? ?? 68 db 79 40 00 ff 35 84 5b 40 00 e8 ?? ?? ?? ?? 68 d1 79 40 00 ff 35 c0 5b 40 00 e8 ?? ?? ?? ?? 83 c4 20 68 5d 33 40 00 68 e8 ?? ?? ?? ?? 9a 02 00 00 ff 35 c4 5b 40 00 e8 ?? ?? ?? ?? a3 34 5c 40 00 68 c4 79 40 00}  //weight: 2, accuracy: Low
        $x_1_2 = "I-Worm.Gigu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


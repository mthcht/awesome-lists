rule TrojanDropper_Win32_Mader_B_2147606639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Mader.gen!B"
        threat_id = "2147606639"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Mader"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 10 7d 21 8b ?? ?? ?? ff ff 8b 84 ?? ?? ?? ff ff 2d ?? ?? ?? ?? 8b 8d ?? ?? ff ff 88 84 0d ?? ?? ff ff eb}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 4d fb 33 c1 1d 00 89 85 ?? ?? ff ff 8b ?? ?? ?? ff ff 3b ?? 10 7d ?? 8b ?? 08 03 ?? ?? ?? ff ff 0f b6}  //weight: 2, accuracy: Low
        $x_1_3 = ">VmImgDescriptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


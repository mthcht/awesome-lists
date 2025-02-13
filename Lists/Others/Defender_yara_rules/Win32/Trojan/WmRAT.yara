rule Trojan_Win32_WmRAT_GA_2147928645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WmRAT.GA!MTB"
        threat_id = "2147928645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WmRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 64 ff d6 6a 01 e8 ?? ?? ?? ?? 83 c4 04 3b c7}  //weight: 1, accuracy: Low
        $x_1_2 = {88 19 4a 41 47 4e 85 d2 ?? ?? 5f 49 5e b8 7a 00 07 80}  //weight: 1, accuracy: Low
        $x_2_3 = {6a 00 b8 04 00 00 00 2b c6 50 8d 0c 3e 51 52 ff ?? 83 f8 ff ?? ?? 03 f0 83 fe 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


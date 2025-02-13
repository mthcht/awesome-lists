rule Virus_Win32_Android_HNA_2147925580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Android.HNA!MTB"
        threat_id = "2147925580"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Android"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 00 8d 45 f4 50 8d 95 70 ff ff ff b9 80 00 00 00 8b c7}  //weight: 1, accuracy: High
        $x_1_2 = {2e 65 78 65 00 00 00 00 53 61 6c 75 74 20 44 65}  //weight: 1, accuracy: High
        $x_1_3 = {c6 00 02 ff 36 68 ?? ?? ?? ?? 8b c3 33 d2 52 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


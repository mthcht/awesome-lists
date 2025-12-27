rule Trojan_Win32_Badaudio_YBE_2147958172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Badaudio.YBE!MTB"
        threat_id = "2147958172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Badaudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe c0 88 01 31 c0 0f b6 4c 04 40 30 0c 1e 43 40 39 dd}  //weight: 1, accuracy: High
        $x_10_2 = {8a 41 06 32 47 06 88 44 24 07 88 41 06 8a 41 07 32 47 07 88 44 24 08 88 41 07 8a 41 08 32 47 08 88 41 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


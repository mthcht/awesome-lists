rule Trojan_Win32_BadAudio_DA_2147958179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadAudio.DA!MTB"
        threat_id = "2147958179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadAudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 c5 19 c1 c7 0e 01 ?? ?? ?? 31 ef c1 eb 03 31}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 c7 0f 8b ?? ?? ?? ?? ?? c1 c3 0d 31 fb c1 ea 0a 31}  //weight: 10, accuracy: Low
        $x_1_3 = "SystemFunction036" ascii //weight: 1
        $x_1_4 = "6666666666666666\\\\\\\\\\\\\\\\\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


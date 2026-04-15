rule Trojan_Win32_Crun_CQ_2147967058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crun.CQ!MTB"
        threat_id = "2147967058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 0f 67 e8 f3 0f 6f 40 ?? 66 0f fc 2d ?? ?? ?? ?? 66 0f ef e8 0f 11 68 ?? 39 d0 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Privateloader_ASR_2147897552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Privateloader.ASR!MTB"
        threat_id = "2147897552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Privateloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "28 107 92 100 103 28 83" ascii //weight: 1
        $x_1_2 = "97 91 104 100 91 98 41 40 36 90 98 98" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


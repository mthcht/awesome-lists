rule TrojanDownloader_Win32_Gippers_VI_2147744666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gippers.VI!MTB"
        threat_id = "2147744666"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gippers"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UServerCreate" ascii //weight: 1
        $x_1_2 = "iloverabbit" ascii //weight: 1
        $x_1_3 = "<<FILES:%d   INJECT:%d>>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


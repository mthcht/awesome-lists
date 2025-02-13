rule Trojan_Win32_BaseLoader_MR_2147776996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BaseLoader.MR!MTB"
        threat_id = "2147776996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BaseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 02 28 [0-4] 06 6f [0-4] 72 [0-4] 72 [0-4] 72 [0-4] 28 [0-5] 28 [0-4] 72 [0-5] 28 [0-4] 26 2a 21 00 02 03 72 [0-4] 72 [0-4] 72 [0-4] 28 [0-4] 16 28 [0-4] 74}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "StartsWith" ascii //weight: 1
        $x_1_4 = "EndsWith" ascii //weight: 1
        $x_1_5 = "ToChar" ascii //weight: 1
        $x_1_6 = "ToString" ascii //weight: 1
        $x_1_7 = "ToByte" ascii //weight: 1
        $x_1_8 = "ToInt32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


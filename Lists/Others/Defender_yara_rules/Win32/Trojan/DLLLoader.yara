rule Trojan_Win32_DLLLoader_EC_2147833705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLLoader.EC!MTB"
        threat_id = "2147833705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {8b 4c b2 04 33 0c b2 23 cb 33 0c b2 8b c1 d1 e9 83 e0 01 33 0c 85 ?? ?? ?? ?? 33 8c b2 ?? ?? ?? ?? 89 0c b2 46 81 fe e3 00 00 00 7c d3}  //weight: 7, accuracy: Low
        $x_1_2 = "qbot4\\dll_dropper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


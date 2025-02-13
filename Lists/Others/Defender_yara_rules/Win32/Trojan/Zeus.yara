rule Trojan_Win32_Zeus_RDA_2147840121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zeus.RDA!MTB"
        threat_id = "2147840121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\{A8A26449-80E6-8096-14C5-6C9A9FB634F5}" wide //weight: 1
        $x_1_2 = "{3ED9D66C-32C3-16ED-14C5-6C9A9FB634F5}" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Lygaza" wide //weight: 1
        $x_1_4 = "C:\\Users\\admin\\AppData\\Roaming\\Lihu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


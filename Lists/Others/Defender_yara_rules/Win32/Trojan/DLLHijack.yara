rule Trojan_Win32_DLLHijack_DF_2147939451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.DF!MTB"
        threat_id = "2147939451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 34 0f 02 de 8a 14 1f 88 14 0f 88 34 1f 02 d6 0f b6 d2 8a 14 17 8a 0c 06 32 ca 5a 88 0c 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


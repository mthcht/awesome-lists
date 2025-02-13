rule Trojan_Win32_Zenload_RH_2147848538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenload.RH!MTB"
        threat_id = "2147848538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 70 72 65 61 64 2e 65 78 65 00 00 63 6d 64 20 2f 63 20 63 73 63 72 69 70 74 20 63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 76 62 73 2e 76 62 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


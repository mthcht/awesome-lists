rule Trojan_Win32_ScarletFlash_GMC_2147891939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScarletFlash.GMC!MTB"
        threat_id = "2147891939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScarletFlash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 8b 5c 24 08 8a 03 8a 4c 24 0c d2 c0 32 c1 88 03 5b}  //weight: 10, accuracy: High
        $x_1_2 = "HWCYlEZnDYkNj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


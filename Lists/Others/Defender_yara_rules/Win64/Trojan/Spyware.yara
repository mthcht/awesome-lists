rule Trojan_Win64_Spyware_NV_2147920283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Spyware.NV!MTB"
        threat_id = "2147920283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Spyware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e8 a8 5b 00 00 48 8b 4c 24 30 e8 ee ba 01 00 8b d0 33 c9 e8 75 be 01 00 ba 01 00 00 00 b9 09 00 00 00 e8 66 be 01 00 48 8b 4c 24 30}  //weight: 2, accuracy: High
        $x_1_2 = "BraveSoftwareBrave-Browsertrying to open brave state file" ascii //weight: 1
        $x_1_3 = "Sending Brave cookies" ascii //weight: 1
        $x_1_4 = "[Steelerino 1.0] executed on target:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


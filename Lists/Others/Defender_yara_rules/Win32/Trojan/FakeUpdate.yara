rule Trojan_Win32_FakeUpdate_AFU_2147909731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeUpdate.AFU!MTB"
        threat_id = "2147909731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeUpdate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


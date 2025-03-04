rule Trojan_Win32_LummaStealerSlip_A_2147935080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerSlip.A!MTB"
        threat_id = "2147935080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerSlip"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 da e8 a5 c7 fa ff c1 c1 05 81 c6 41 66 4e 3b 81 05 78 29 64 01 82 9a 0f 88 e8 0c 66 0d 00 81 f7 75 c6 27 e5 81 f2 26 d2 15 1f 41 03 c5 0b 0d aa 2f 64 01 33 f8 c1 cb 0e 81 c3 ed 78 95 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


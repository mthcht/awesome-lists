rule TrojanDropper_Win32_FakeAV_DG_2147816500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/FakeAV.DG!MTB"
        threat_id = "2147816500"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 18 8a 54 24 13 30 14 08 40 3b c5 72 f0}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


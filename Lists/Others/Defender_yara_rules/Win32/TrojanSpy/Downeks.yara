rule TrojanSpy_Win32_Downeks_SK_2147838534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Downeks.SK!MTB"
        threat_id = "2147838534"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Downeks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sergey Kloubkov" ascii //weight: 1
        $x_1_2 = "gitlab.com/0coderproducts/myanus/-/raw/master/storage/text.txt" ascii //weight: 1
        $x_1_3 = "Heuristic.Susp.Bat (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


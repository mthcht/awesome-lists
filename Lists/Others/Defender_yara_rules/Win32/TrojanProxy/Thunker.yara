rule TrojanProxy_Win32_Thunker_F_2147607862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Thunker.F"
        threat_id = "2147607862"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Thunker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7f 0d ff 44 24 10 83 7c 24 10 05 7c ?? eb 08 c7 44 24 18 01 00 00 00 68 ?? ?? 00 10 68 ?? 31 00 10 0d 00 ff ?? 55 e8 ?? (02|03) 00 00 83 c4 34 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


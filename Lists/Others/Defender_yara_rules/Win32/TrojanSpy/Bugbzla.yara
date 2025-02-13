rule TrojanSpy_Win32_Bugbzla_PQ_2147742078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bugbzla.PQ"
        threat_id = "2147742078"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bugbzla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b fb 85 f6 75 1b 83 c8 ff e9 a1 00 00 00 66 3b c1 74 01 47 56 e8 bd 2d 00 00 59 8d 34 46 83 c6 02 0f b7 06 6a 3d 59 66 85 c0 75 e2 8d 47 01}  //weight: 1, accuracy: High
        $x_1_2 = "http://www.haibugmm.com/ba/yfctbzla" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


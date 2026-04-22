rule Trojan_Win32_Passview_MA_2147813451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Passview.MA!MTB"
        threat_id = "2147813451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Passview"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 41 b5 f8 3b a1 ?? ?? ?? ?? 3a 4f ad 33 99 ?? ?? ?? ?? 0c 00 aa 00 60 d3 93}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 4d 61 69 6e 00 0d 01 2e 00 c4 a7 ca de d5 f9 b0 d4 b8 f6 d0 d4 bb af b9 a4 be df 20 2d 20 57 61 72 4d 70 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


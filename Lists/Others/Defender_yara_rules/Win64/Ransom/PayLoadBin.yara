rule Ransom_Win64_PayLoadBin_A_2147782105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PayLoadBin.A"
        threat_id = "2147782105"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PayLoadBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 c7 44 24 38 ff ff ff ff c7 44 24 30 59 dc 00 00 8b 05 ?? ?? ?? ?? 89 44 24 4c 48 8b ?? ?? ?? ?? ?? 48 89 44 24 40 b9 02 00 00 00 ff ?? ?? ?? 8b 44 24 30 2d 19 dc 00 00 89 44 24 20 41 b9 00 30 00 00 44 8b 44 24 4c 33 d2 48 8b 4c 24 38 ff [0-60] 48 8d 84 01 20 73 1c 00}  //weight: 4, accuracy: Low
        $x_1_2 = "{aa5b6a80-b834-11d0-932f-00a0c90dcaa9}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


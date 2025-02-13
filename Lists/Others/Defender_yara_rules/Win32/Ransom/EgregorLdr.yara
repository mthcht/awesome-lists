rule Ransom_Win32_EgregorLdr_A_2147777810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EgregorLdr.A"
        threat_id = "2147777810"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EgregorLdr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 4d d3 34 4d 01 43 ?? 8b c3 39 50 ?? 8b d3 8b 5d f8 1b c0 f7 d8}  //weight: 2, accuracy: Low
        $x_2_2 = {05 34 4d d3 34 01 42 ?? 39 7a ?? 8b fa 1b c0 f7 d8}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f8 01 0f 8e ?? ?? ?? ?? 8b c7 25 ff 0f 00 00 6a ?? 5e 3d f0 0f}  //weight: 2, accuracy: Low
        $x_1_4 = "expand 32-byte k" ascii //weight: 1
        $x_1_5 = "expand 16 byte k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


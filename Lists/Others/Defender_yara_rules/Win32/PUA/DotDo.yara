rule PUA_Win32_DotDo_J_259254_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/DotDo.J!ibt"
        threat_id = "259254"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "DotDo"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 28 0f 00 00 0a 0b 16 0c 2b 17 07 08 9a 0a 02 17 58 10 00 02 17 31 06 06 6f 10 00 00 0a 08 17 58 0c 08 07 8e 69 32 e3}  //weight: 1, accuracy: High
        $x_1_2 = {16 72 01 00 00 70 72 01 00 00 70 28 01 00 00 06 16 72 ?? 00 00 70 72 ?? 00 00 70 28 01 00 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


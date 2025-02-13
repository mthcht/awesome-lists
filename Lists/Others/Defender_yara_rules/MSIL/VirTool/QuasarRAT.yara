rule VirTool_MSIL_QuasarRAT_ASC_2147731546_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/QuasarRAT.ASC!bit"
        threat_id = "2147731546"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {da 17 d6 8d 14 00 00 01 ?? 28 1d 00 00 0a 72 01 00 00 70 6f 1e 00 00 0a ?? ?? ?? 2b 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {8e b7 2f 26 ?? 16 30 00 ?? ?? 8e b7 17 da ?? da 02 ?? 91 02 02 8e b7 17 da 91 61 ?? ?? ?? 8e b7 5d 91 61 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


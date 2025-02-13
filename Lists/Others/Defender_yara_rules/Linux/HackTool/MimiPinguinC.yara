rule HackTool_Linux_MimiPinguinC_A_2147776108_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MimiPinguinC.A!!MimiPinguinC.A"
        threat_id = "2147776108"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MimiPinguinC"
        severity = "High"
        info = "MimiPinguinC: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 11 8f f0 ?? ?? ?? 0f 11 47 10 0f 11 47 30 0f 11 87 00 01 ?? ?? 0f 11 87 b0 01}  //weight: 10, accuracy: Low
        $x_10_2 = {48 89 87 a8 ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 97 a8 01 ?? ?? 66 0f 6f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


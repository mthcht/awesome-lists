rule Backdoor_MSIL_nJRat_FVJ_2147828736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/nJRat.FVJ!MTB"
        threat_id = "2147828736"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "nJRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 06 08 1e 5a 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 00 08 17 58 0c 08 07 8e 69 17 59 fe 02 16 fe 01 13 05 11 05 2d d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


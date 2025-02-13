rule Backdoor_MSIL_WarzoneRat_AWZ_2147852024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WarzoneRat.AWZ!MTB"
        threat_id = "2147852024"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 59 0c 2b 1c 00 07 06 08 6f ?? ?? ?? 0a 0d 12 03 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 08 17 59 0c 00 08 15 fe 01 16 fe 01 13 04 11 04 2d d7}  //weight: 2, accuracy: Low
        $x_1_2 = "Nialon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


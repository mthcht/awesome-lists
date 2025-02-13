rule Backdoor_MSIL_Teweave_A_2147695317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Teweave.A"
        threat_id = "2147695317"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Teweave"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 59 18 5b 1a 6f ?? ?? ?? ?? 16 0c 2b 2a 06 08 06 25 13 05 08 25 13 06 11 05 11 06 6f ?? ?? ?? ?? 07 d2 59 d2 25 13 07 6f ?? ?? ?? ?? 11 07 6f ?? ?? ?? ?? 08 17 58}  //weight: 5, accuracy: Low
        $x_1_2 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_3 = "[SYN]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


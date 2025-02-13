rule Backdoor_MSIL_Soblacod_A_2147711488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Soblacod.A"
        threat_id = "2147711488"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Soblacod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "camera" ascii //weight: 1
        $x_1_2 = "gfxScreenshot" ascii //weight: 1
        $x_1_3 = {6c 61 73 74 4b 65 79 00 4c 6f 67 73}  //weight: 1, accuracy: High
        $x_1_4 = {45 78 78 70 65 72 00 57 52 4b}  //weight: 1, accuracy: High
        $x_1_5 = "|Function - Disabled|" wide //weight: 1
        $x_1_6 = {5c 00 74 00 74 00 6d 00 70 00 2e 00 70 00 6e 00 67 00 ?? ?? 5b 00 30 00 5d 00 2a 00 ?? ?? 5b 00 31 00 5d 00 2a 00}  //weight: 1, accuracy: Low
        $x_1_7 = {23 00 7c 00 20 00 5b 00 [0-32] 5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


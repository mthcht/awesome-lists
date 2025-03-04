rule Backdoor_MSIL_AsyncRat_A_2147794210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRat.A!MTB"
        threat_id = "2147794210"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 1f 1a 28 ?? ?? ?? 0a 72 53 00 00 70 28 ?? ?? ?? 0a 17 28 ?? ?? ?? 0a 7e ?? ?? ?? 0a 02 72 63 00 00 70 28 ?? ?? ?? 06 17 6f ?? ?? ?? 0a 72 c5 00 00 70 1f 1a}  //weight: 1, accuracy: Low
        $x_1_2 = "COM Surrogate" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AsyncRat_PA7_2147819287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AsyncRat.PA7!MTB"
        threat_id = "2147819287"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 7e 53 01 00 04 07 7e 53 01 00 04 07 91 20 9a 03 00 00 59 d2 9c 00 07 17 58 0b 07 7e 53 01 00 04 8e 69 fe 04 0c 08 2d d7}  //weight: 2, accuracy: High
        $x_2_2 = "http://serverupdates48.ga/test" ascii //weight: 2
        $x_1_3 = "HttpWebRequest" ascii //weight: 1
        $x_1_4 = "CarRentalSystem\\obj\\Debug\\Dash.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


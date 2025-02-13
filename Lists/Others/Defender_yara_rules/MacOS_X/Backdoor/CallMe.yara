rule Backdoor_MacOS_X_CallMe_A_2147681322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/CallMe.A"
        threat_id = "2147681322"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "CallMe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {77 72 69 74 65 54 6f 46 69 6c 65 3a 61 74 6f 6d 69 63 61 6c 6c 79 3a 00 64 69 63 74 69 6f 6e 61 72 79 57 69 74 68 4f 62 6a 65 63 74 73 41 6e 64 4b 65 79 73 3a}  //weight: 4, accuracy: High
        $x_2_2 = "/tmp/tmpAddressbook.vcf" ascii //weight: 2
        $x_2_3 = "%s/Library/LaunchAgents/.systm" ascii //weight: 2
        $x_2_4 = "/tmp/__system" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


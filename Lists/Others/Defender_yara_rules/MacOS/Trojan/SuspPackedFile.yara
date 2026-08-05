rule Trojan_MacOS_SuspPackedFile_A_2147975293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspPackedFile.A"
        threat_id = "2147975293"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspPackedFile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "freshfix.bootstrap" ascii //weight: 2
        $x_1_2 = "-frag" ascii //weight: 1
        $x_1_3 = "setup-55554" ascii //weight: 1
        $x_1_4 = "_getsectiondata" ascii //weight: 1
        $x_1_5 = "_OSAExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_MacOS_Leap_A_2147745524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Leap.A!MTB"
        threat_id = "2147745524"
        type = "Trojan"
        platform = "MacOS: "
        family = "Leap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apphook.tar" ascii //weight: 1
        $x_1_2 = "oompa" ascii //weight: 1
        $x_1_3 = "(kMDItemKind == 'Application') && (kMDItemLastUsedDate >= $time.this_month)" ascii //weight: 1
        $x_1_4 = {7c 00 e2 78 7c 1e 11 ae 38 42 00 01 7c 1e 10 ae 7c 00 07 74 2f 80 00 00 40 9e ff e8 38 21 00 50 7f c3 f3 78 80 01 00 08 bb 81 ff f0 7c 08 03 a6 4e 80 00 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


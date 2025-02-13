rule Ransom_MacOS_Crypat_A_2147745272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Crypat.A!MTB"
        threat_id = "2147745272"
        type = "Ransom"
        platform = "MacOS: "
        family = "Crypat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YWNsZSBvciBzdGFydCBvYnRhaW5pbmcgQklUQ09JTiBOT1chICwgYW5kIHJlc3RvcmUgWU9VUiBEQVRBIHRoZSBlYXN5IHdheQ0KSWYgWW91IGhhdmUgcmVhbGx5IHZhbHVhYmxlIERBVEEsIHlvdS" ascii //weight: 1
        $x_1_2 = "Press START button to crack/patch " ascii //weight: 1
        $x_1_3 = "/Desktop/HOW_TO_DECRYPT" ascii //weight: 1
        $x_1_4 = "/Movies/README!.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_Crypat_B_2147748003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Crypat.B!MTB"
        threat_id = "2147748003"
        type = "Ransom"
        platform = "MacOS: "
        family = "Crypat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YWNsZSBvciBzdGFydCBvYnRhaW5pbmcgQklUQ09JTiBOT1chICwgYW5kIHJlc3RvcmUgWU9VUiBEQVRBIHRoZSBlYXN5IHdheQ0KSWYgWW91IGhhdmUgcmVhbGx5IHZhbHVhYmxlIERBVEEsIHlvdS" ascii //weight: 1
        $x_1_2 = "Press START button to crack/patch " ascii //weight: 1
        $x_1_3 = "/Desktop/HOW_TO_DECRYPT" ascii //weight: 1
        $x_1_4 = "/Desktop/DECRYPT" ascii //weight: 1
        $x_1_5 = "{}.crypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


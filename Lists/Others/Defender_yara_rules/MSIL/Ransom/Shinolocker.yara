rule Ransom_MSIL_Shinolocker_AA_2147903118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Shinolocker.AA!MTB"
        threat_id = "2147903118"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shinolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShinoLocker" ascii //weight: 1
        $x_1_2 = {44 65 63 72 79 70 74 00 45 6e 63 72 79 70 74 00 43 6f 6e 76 65 72 74}  //weight: 1, accuracy: High
        $x_1_3 = {73 65 74 5f 42 6c 6f 63 6b 53 69 7a 65 00 73 65 74 5f 4b 65 79 53 69 7a 65 00 73 65 74 5f 50 61 64 64 69 6e 67 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win64_Bloody_ZB_2147904706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Bloody.ZB!MTB"
        threat_id = "2147904706"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Bloody"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CRYPT" wide //weight: 1
        $x_1_2 = "All Encrypted files can be reversed to original form" ascii //weight: 1
        $x_1_3 = "bl00dyadmin" ascii //weight: 1
        $x_1_4 = "I have stolen All Your Databases" ascii //weight: 1
        $x_1_5 = "ALL files oN Your Entire Network Servers and Connected Devices are Encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


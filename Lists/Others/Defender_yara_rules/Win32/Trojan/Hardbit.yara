rule Trojan_Win32_Hardbit_PB_2147837681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hardbit.PB!MTB"
        threat_id = "2147837681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hardbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README.txt" wide //weight: 1
        $x_1_2 = "YOUR FILES ARE STOLEN AND ENCRYPTED" ascii //weight: 1
        $x_1_3 = "purchase of a private key" ascii //weight: 1
        $x_1_4 = "rename or modify encrypted files" ascii //weight: 1
        $x_1_5 = "pay ransom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Pluroxs_SK_2147755320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pluroxs.SK!MTB"
        threat_id = "2147755320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pluroxs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "google-public-dns-a.google.com" ascii //weight: 1
        $x_1_2 = "WinSock 2.0" ascii //weight: 1
        $x_1_3 = "/MPGoodStatus" ascii //weight: 1
        $x_1_4 = "E:\\OldSoftware\\Generating\\Crypto\\crypto.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


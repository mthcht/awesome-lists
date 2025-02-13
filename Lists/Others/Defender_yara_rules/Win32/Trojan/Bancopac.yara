rule Trojan_Win32_Bancopac_2147632091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bancopac"
        threat_id = "2147632091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancopac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6e 00 73 00 31 00 2e 00 6e 00 61 00 74 00 61 00 6c 00 6e 00 6f 00 73 00 73 00 6f 00 2e 00 69 00 6e 00 66 00 6f 00 3a 00 38 00 30 00 38 00 32 00 2f 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 70 00 61 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "user_pref(\"network.proxy.autoconfig_url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


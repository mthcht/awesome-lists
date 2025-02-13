rule Trojan_Win32_Cymowon_A_2147730456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cymowon.A"
        threat_id = "2147730456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cymowon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Get-WMIobject -Namespace root\\Subscription -Class __FilterToConsumerBinding" wide //weight: 1
        $x_1_2 = {69 00 65 00 78 00 [0-4] 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


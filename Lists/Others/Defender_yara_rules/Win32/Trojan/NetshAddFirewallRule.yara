rule Trojan_Win32_NetshAddFirewallRule_A_2147933241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetshAddFirewallRule.A!ibt"
        threat_id = "2147933241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetshAddFirewallRule"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 72 00 75 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 [0-2] 73 00 62 00 66 00 77 00 72 00 75 00 6c 00 65 00 [0-10] 64 00 69 00 72 00 3d 00 69 00 6e 00 [0-10] 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 6c 00 6c 00 6f 00 77 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_NetShFirewallRuleAdd_A_2147767673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetShFirewallRuleAdd.A"
        threat_id = "2147767673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetShFirewallRuleAdd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 73 00 68 00 [0-16] 61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 [0-5] 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 [0-5] 61 00 64 00 64 00 [0-5] 72 00 75 00 6c 00 65 00 [0-5] 6e 00 61 00 6d 00 65 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


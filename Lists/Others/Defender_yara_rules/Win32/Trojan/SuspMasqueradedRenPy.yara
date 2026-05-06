rule Trojan_Win32_SuspMasqueradedRenPy_EB_2147968548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspMasqueradedRenPy.EB"
        threat_id = "2147968548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMasqueradedRenPy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 73 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $n_1_2 = "***__c8a10b4c-0298-4a21-9dc1-4a843a38e4b4__***" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


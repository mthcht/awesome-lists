rule Trojan_Win32_Shimming_A_2147924249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shimming.A"
        threat_id = "2147924249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shimming"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdbinst -q" ascii //weight: 1
        $x_1_2 = "ai_shim_test.sdb" ascii //weight: 1
        $n_10_3 = "sdbinst -q -u" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


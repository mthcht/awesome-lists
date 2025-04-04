rule Trojan_Win32_Shimming_B_2147937933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shimming.B"
        threat_id = "2147937933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shimming"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sdbinst -q" ascii //weight: 2
        $x_2_2 = "ai_shim_test.sdb" ascii //weight: 2
        $n_10_3 = "sdbinst -q -u" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


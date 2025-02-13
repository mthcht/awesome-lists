rule Trojan_Win32_TrojanisedLolMiner_A_2147813272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrojanisedLolMiner.A"
        threat_id = "2147813272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrojanisedLolMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot5080947553:AAFY7o6U7eYnp2cSVZgI5zrrBthTLC1DEQo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


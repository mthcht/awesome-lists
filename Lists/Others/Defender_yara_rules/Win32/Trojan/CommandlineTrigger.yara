rule Trojan_Win32_CommandlineTrigger_A_2147765043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CommandlineTrigger.A"
        threat_id = "2147765043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CommandlineTrigger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "istest456" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


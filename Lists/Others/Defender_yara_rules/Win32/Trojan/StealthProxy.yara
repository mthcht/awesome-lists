rule Trojan_Win32_StealthProxy_B_2147641259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealthProxy.B"
        threat_id = "2147641259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealthProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\wupdte002.com" ascii //weight: 1
        $x_1_2 = "vamoqvamo" ascii //weight: 1
        $x_2_3 = "user_pref(\"network" ascii //weight: 2
        $x_3_4 = {8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 3c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


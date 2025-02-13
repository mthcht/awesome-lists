rule Trojan_Win32_MPTamperAdRun_B_2147812065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MPTamperAdRun.B"
        threat_id = "2147812065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MPTamperAdRun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "advancedrun" wide //weight: 10
        $x_10_2 = "stop windefend" wide //weight: 10
        $x_1_3 = "commandline" wide //weight: 1
        $x_1_4 = "runas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


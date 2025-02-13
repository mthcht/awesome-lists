rule Trojan_Win32_LoggerMachete_B_2147741868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LoggerMachete.B"
        threat_id = "2147741868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LoggerMachete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eJzVPGl32ziS3/0rNPTzio" ascii //weight: 1
        $x_1_2 = "py2exe\\boot_common.pyt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


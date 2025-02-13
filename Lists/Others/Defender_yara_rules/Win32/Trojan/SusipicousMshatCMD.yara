rule Trojan_Win32_SusipicousMshatCMD_S01_2147933316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusipicousMshatCMD.S01"
        threat_id = "2147933316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusipicousMshatCMD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-64] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusipicousMshatCMD_S02_2147933317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusipicousMshatCMD.S02"
        threat_id = "2147933317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusipicousMshatCMD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $n_10_2 = ".hta" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


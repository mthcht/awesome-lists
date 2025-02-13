rule Trojan_Win32_Remnit_2147839346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remnit.psyD!MTB"
        threat_id = "2147839346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remnit"
        severity = "Critical"
        info = "psyD: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {08 80 ec 6c 30 61 00 41 4a 8b da 81 eb 09 58 cd 2f 52 53 8b d4 81 42 00 09 58 cd 2f 5b 5a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


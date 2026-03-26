rule Trojan_Win32_Hijack_ARR_2147965719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hijack.ARR!MTB"
        threat_id = "2147965719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {8a 16 8b f9 8b e9 32 10 40 88 16 83 ef}  //weight: 15, accuracy: High
        $x_5_2 = "POSGrabber_mutated.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


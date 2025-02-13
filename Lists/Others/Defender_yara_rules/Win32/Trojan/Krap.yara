rule Trojan_Win32_Krap_CC_2147811076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krap.CC!MTB"
        threat_id = "2147811076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 30 60 60 61 80 30 72 53 31 db 5b 40 48 80 28 88 53 31 db 5b 80 30 f6 53 31 db 5b 80 00 95 90 80 28 7b 42 4a 80 00 40 43 4b 80 28 11 60 61 80 00 15 40 3d 78 ce 43 00 7e c2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


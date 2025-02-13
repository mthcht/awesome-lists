rule Trojan_Win32_Qmine_NE_2147748461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qmine.NE!MTB"
        threat_id = "2147748461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qmine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\ProgramData\\svchostlong.exe" ascii //weight: 1
        $x_1_2 = {63 6d 64 20 2f 63 20 64 65 6c 20 2f 61 20 2f 66 20 2f 71 20 ?? 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 2a 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


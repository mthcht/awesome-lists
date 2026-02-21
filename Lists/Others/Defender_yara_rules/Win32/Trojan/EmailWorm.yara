rule Trojan_Win32_EmailWorm_PGEW_2147963477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmailWorm.PGEW!MTB"
        threat_id = "2147963477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmailWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {60 00 00 c0 2e 66 6c 68 00 00 00 00 00 10 00 00 00 30 03 00 00 02 00 00 00 20 01 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 72 70 55 72 45 72 62 64 4e 19 00 00 00 40 03 00 00 1a 00 00 00 22 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 70 45 6e 58 44 61 79 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


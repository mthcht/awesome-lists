rule Trojan_Win32_MariaRat_A_2147940909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MariaRat.A!MTB"
        threat_id = "2147940909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Elevation:Administrator!new:{" ascii //weight: 1
        $x_1_2 = "encrypted_key" ascii //weight: 1
        $x_1_3 = "SMTP Password" ascii //weight: 1
        $x_1_4 = "cmd.exe /C ping " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_GhostLocker_YAB_2147978497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostLocker.YAB!MTB"
        threat_id = "2147978497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "ransom_amount" ascii //weight: 6
        $x_1_2 = "ghostlocker" ascii //weight: 1
        $x_1_3 = "Reading BodyEncrypt" ascii //weight: 1
        $x_2_4 = "HTTPinfection_date[ENCRYPTIONID" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


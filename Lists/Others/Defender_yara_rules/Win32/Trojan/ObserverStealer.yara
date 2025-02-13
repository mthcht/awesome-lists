rule Trojan_Win32_ObserverStealer_A_2147890462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ObserverStealer.A!MTB"
        threat_id = "2147890462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ObserverStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "processGrabber" wide //weight: 2
        $x_2_2 = "encryptedPassword\":\"([" ascii //weight: 2
        $x_2_3 = "hostname\":\"([" ascii //weight: 2
        $x_2_4 = "encrypted_key\":\"(.+?)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


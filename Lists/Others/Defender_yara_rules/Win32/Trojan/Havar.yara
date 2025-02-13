rule Trojan_Win32_Havar_RF_2147840988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Havar.RF!MTB"
        threat_id = "2147840988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Havar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ba 20 0a 00 00 8d 04 12 0f af c2 8b c8 0f af c8 8b c2 f7 ea 2b c8 8b c1}  //weight: 2, accuracy: High
        $x_1_2 = "jagvillhadig" ascii //weight: 1
        $x_1_3 = "msiuserdesk.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


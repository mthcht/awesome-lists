rule Trojan_Win32_SBadur_GTV_2147960539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SBadur.GTV!MTB"
        threat_id = "2147960539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "downloadAndExecuteBatScript" ascii //weight: 1
        $x_1_2 = "establishReverseShell_log.txt" ascii //weight: 1
        $x_1_3 = "communicateWithC2_log.txt" ascii //weight: 1
        $x_1_4 = "dljmp2p.com" ascii //weight: 1
        $x_1_5 = "\\terminateSecurityProducts_log.txt" ascii //weight: 1
        $x_1_6 = "\\dumpCredentials_log.txt" ascii //weight: 1
        $x_1_7 = "terminateBackdoorProcess_log.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


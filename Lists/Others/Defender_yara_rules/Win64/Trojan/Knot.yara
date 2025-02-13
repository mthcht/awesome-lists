rule Trojan_Win64_Knot_EH_2147828334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Knot.EH!MTB"
        threat_id = "2147828334"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Knot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows\\system32\\spool\\drivers\\color\\" ascii //weight: 1
        $x_1_2 = "SusCreateFileRetryIfSharingViolation" ascii //weight: 1
        $x_1_3 = "SUS Client Proxy Authentication Credentials" wide //weight: 1
        $x_1_4 = "wuauserv" wide //weight: 1
        $x_1_5 = "ws\\CurrentVersion\\WindowsUpdate\\Test\\Policies" wide //weight: 1
        $x_1_6 = "IsPolicyOverrideAllowed" wide //weight: 1
        $x_1_7 = "DisableAppPublisher" wide //weight: 1
        $x_1_8 = "DisableWindowsUpdateOnlineRevocation" wide //weight: 1
        $x_1_9 = "wuapi.pdb" ascii //weight: 1
        $x_1_10 = "1.3.6.1.4.1.311.72.1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


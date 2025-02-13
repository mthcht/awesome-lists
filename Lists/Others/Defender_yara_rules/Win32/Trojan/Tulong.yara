rule Trojan_Win32_Tulong_XA_2147817509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tulong.XA!MTB"
        threat_id = "2147817509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tulong"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "121.124.124.210" ascii //weight: 1
        $x_1_2 = "\\MyRatServer\\Release\\MyRatServer.pdb" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "GetTickCount64" ascii //weight: 1
        $x_1_5 = "@DOWNFILE" ascii //weight: 1
        $x_1_6 = "Online:%s:%s:%s:%s" ascii //weight: 1
        $x_1_7 = "@UPFILE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


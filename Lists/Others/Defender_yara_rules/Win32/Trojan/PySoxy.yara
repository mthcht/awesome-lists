rule Trojan_Win32_PySoxy_GVA_2147970689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PySoxy.GVA!MTB"
        threat_id = "2147970689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PySoxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "b64.pyc" wide //weight: 10
        $x_10_2 = "-ssl" wide //weight: 10
        $x_10_3 = "-remote_port" wide //weight: 10
        $x_10_4 = "-remote_ip" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


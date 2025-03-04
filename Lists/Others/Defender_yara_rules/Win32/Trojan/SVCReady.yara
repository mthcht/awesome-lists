rule Trojan_Win32_SVCReady_HQ_2147827825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SVCReady.HQ!MTB"
        threat_id = "2147827825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SVCReady"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ETSS8c" ascii //weight: 1
        $x_1_2 = "S5eY98Yn" ascii //weight: 1
        $x_1_3 = "A9okUzHBQez" ascii //weight: 1
        $x_1_4 = "uoIqFvkWcQ" ascii //weight: 1
        $x_1_5 = "function ma(a){return function(b){var c=b.nodeName.toLowerCase();return" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


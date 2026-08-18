rule Ransom_Win32_RustMonitor_YAUA_2147976391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RustMonitor.YAUA!MTB"
        threat_id = "2147976391"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RustMonitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Your files have been encrypted ~~~" ascii //weight: 4
        $x_4_2 = "Do NOT attempt to decrypt files with third-party tools" ascii //weight: 4
        $x_4_3 = "Open our contact portal in Tor Browser." ascii //weight: 4
        $x_4_4 = "Download and install Tor Browser" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


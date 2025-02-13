rule Worm_Win32_Scslcraft_A_2147752151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Scslcraft.A!MTB"
        threat_id = "2147752151"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Scslcraft"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scanslam [-r<n>] <host1> <host2-host3>" ascii //weight: 1
        $x_1_2 = "err: sendto(%d.%d.%d.%d:%d) %d" ascii //weight: 1
        $x_1_3 = "= crafted packet in <file>" ascii //weight: 1
        $x_1_4 = "= DoS rather than scan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


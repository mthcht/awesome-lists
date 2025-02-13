rule Trojan_Win32_NukeSpeed_EC_2147923923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NukeSpeed.EC!MTB"
        threat_id = "2147923923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NukeSpeed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blacklist found" ascii //weight: 1
        $x_1_2 = "c:\\tmp\\blk.dat" ascii //weight: 1
        $x_1_3 = "c:\\tmp\\info.dat" ascii //weight: 1
        $x_1_4 = "c:\\users\\public\\sck.dat" ascii //weight: 1
        $x_1_5 = "c:\\tmp\\_DMP\\TMPL_%d_%d.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


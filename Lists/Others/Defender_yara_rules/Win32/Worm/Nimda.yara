rule Worm_Win32_Nimda_Q_2147620492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nimda.Q"
        threat_id = "2147620492"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nimda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "boundary=\"====_ABC123456j7890DEF_====" ascii //weight: 1
        $x_1_2 = "<iframe src=3Dcid:EA4DMGBP9p height=3D0 width=3D0>" ascii //weight: 1
        $x_1_3 = "/msadc/..%255c../..%255c../..%255c/..%c1%1c../..%c1%1c../..%c1%1c.." ascii //weight: 1
        $x_1_4 = "tftp%%20-i%%20%s%%20GET%%20" ascii //weight: 1
        $x_1_5 = "/_vti_bin/..%255c../..%255c../..%255c.." ascii //weight: 1
        $x_1_6 = "-dontrunold" ascii //weight: 1
        $x_1_7 = "http://members.xoom.com/m53group" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


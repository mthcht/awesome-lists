rule Trojan_Win64_VenusStealer_AMTB_2147974147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VenusStealer!AMTB"
        threat_id = "2147974147"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VenusStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%sjunk_%08x_%08x.tmp" ascii //weight: 1
        $x_1_2 = "del /f /q C:\\Windows\\Prefetch\\*.*" ascii //weight: 1
        $x_1_3 = "http://31.77.168.180:5000/umvbr.bin" ascii //weight: 1
        $x_1_4 = "\\Release\\Pov.pdb" ascii //weight: 1
        $x_1_5 = "JunkClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


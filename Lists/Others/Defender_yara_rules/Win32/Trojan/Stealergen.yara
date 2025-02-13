rule Trojan_Win32_Stealergen_VHO_2147808279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealergen.VHO!MTB"
        threat_id = "2147808279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://test.besthotel360.com/001/puppet.Txt" ascii //weight: 2
        $x_2_2 = "hkernY2.dll" ascii //weight: 2
        $x_2_3 = "VirtualProtect" ascii //weight: 2
        $x_2_4 = "HTTP/1.1" ascii //weight: 2
        $x_2_5 = "HTTP/1.0" ascii //weight: 2
        $x_2_6 = "Accept-Language: zh-cn" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


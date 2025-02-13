rule Trojan_Win64_Disttl_RS_2147909836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Disttl.RS!MTB"
        threat_id = "2147909836"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Disttl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\x64\\Release\\Anowez Proxy.pdb" ascii //weight: 1
        $x_1_2 = "\\Growtopia\\cache\\items.dat" ascii //weight: 1
        $x_1_3 = "\\AppData\\Local\\Growtopia\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


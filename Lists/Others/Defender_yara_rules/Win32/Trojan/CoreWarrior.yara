rule Trojan_Win32_CoreWarrior_DA_2147915896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoreWarrior.DA!MTB"
        threat_id = "2147915896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoreWarrior"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "libgcj_s.dll" ascii //weight: 1
        $x_1_2 = "wa rifaien yanje v1.0" ascii //weight: 1
        $x_10_3 = "http://wecan.hasthe.techno" ascii //weight: 10
        $x_1_4 = "logy/upload" ascii //weight: 1
        $x_1_5 = "CONNECT_ONLY is required!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


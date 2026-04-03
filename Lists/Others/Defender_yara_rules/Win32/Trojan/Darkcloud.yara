rule Trojan_Win32_Darkcloud_RR_2147954582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkcloud.RR!MTB"
        threat_id = "2147954582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://fiberfoodsgroup.atwebpages.com/ghytyhjfgjgjf/juhygtfrdg/hyg55467576/6788876554345656654443656.dll" wide //weight: 1
        $x_1_2 = "https://api.telegram.org/bot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Darkcloud_RR_2147954582_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkcloud.RR!MTB"
        threat_id = "2147954582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sfYMosuhjviknMOWKRzdDF" wide //weight: 1
        $x_1_2 = "kTdgxAjXKceWYVSSMjANLsRpPrFnryTyOmMRlLeFG" wide //weight: 1
        $x_1_3 = "eyHMzXyFQuhSIsePGpWAcFH" wide //weight: 1
        $x_1_4 = "RwvimUlCcPNzOilBJPICPdgylodbHdYRZcmKFRsotjn" wide //weight: 1
        $x_1_5 = "RSpHWRKHJLfBaebSZwrckEYwCoNApuGFpU" wide //weight: 1
        $x_1_6 = "qhFSZSItyoOcNaqBqKtqeXeYmFhcvVMU" wide //weight: 1
        $x_1_7 = "EkayJFZpdkmJQCMZVxxyEj" wide //weight: 1
        $x_1_8 = "GFvcFDeQwcVFrKhInZsXPvj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


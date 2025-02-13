rule Trojan_Win32_Phexeph_A_2147658621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phexeph.A"
        threat_id = "2147658621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phexeph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@file_exists(\"C:/Windows/system/\".PcName.\".exe\")" ascii //weight: 1
        $x_1_2 = "CurrentVersion\\\\Run /v AdobeUpdate" ascii //weight: 1
        $x_1_3 = "if (VirtualBx ==\"ANTIVIRUS\"){exit;}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


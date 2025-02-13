rule Trojan_Win32_Gudra_A_2147707017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gudra.A"
        threat_id = "2147707017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gudra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 3d 21 67 75 64 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 20 6d 6f 64 65 2e}  //weight: 1, accuracy: Low
        $x_1_2 = "kz.baiduddn.com:33900" ascii //weight: 1
        $x_1_3 = "kz.weibocdn.net:33900" ascii //weight: 1
        $x_1_4 = "61.139.2.69:53" ascii //weight: 1
        $x_1_5 = "GudrAlive" wide //weight: 1
        $x_1_6 = "GudrFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


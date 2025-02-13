rule Trojan_Win32_Pulcare_A_2147692228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pulcare.A"
        threat_id = "2147692228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pulcare"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "iuuqt;00" ascii //weight: 1
        $x_1_2 = "h{soruhu1h{h" wide //weight: 1
        $x_1_3 = "%s?v=1&tid=%s&cid=%s&t=event&ec=%s&ea=%s&el=%s&z=%d&de=UTF-8&cd1=%s&cd2=%s&cd3=%s" ascii //weight: 1
        $x_1_4 = "%s?id=%s&r=&lg=zh-cn&ntime=none&cnzz_eid=%s&showp=1920x1080&ei=%s|%s|%s|0|&h=1&rnd=%u" ascii //weight: 1
        $x_1_5 = "%s\\plugin.dat" wide //weight: 1
        $x_1_6 = "%s\\CarefreePlugin.dll" wide //weight: 1
        $x_1_7 = {6f 00 70 00 65 00 6e 00 ?? ?? ?? ?? 2f 00 73 00 20 00 2f 00 75 00 20 00 22 00 25 00 73 00 22 00 ?? ?? ?? ?? 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


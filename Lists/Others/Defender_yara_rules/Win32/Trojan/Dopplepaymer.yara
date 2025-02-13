rule Trojan_Win32_Dopplepaymer_KR_2147761827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dopplepaymer.KR!MTB"
        threat_id = "2147761827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "testapp.exe" ascii //weight: 1
        $x_1_2 = "self.exe" ascii //weight: 1
        $x_1_3 = "TESTAPP.exe" wide //weight: 1
        $x_1_4 = "F:\\ACTUALLIST\\LOGINFIRST!!!\\@RTGWEHW.exe" ascii //weight: 1
        $x_1_5 = "IrwhEbzeh.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


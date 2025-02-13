rule Trojan_Win32_Baidence_MA_2147844569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Baidence.MA!MTB"
        threat_id = "2147844569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Baidence"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "O9TH8Adx.exe" ascii //weight: 2
        $x_2_2 = "6NSpyWWd.exe" ascii //weight: 2
        $x_1_3 = "Cookie: BAIDUID=4551B3A873310A1D9F1D8F3847FADA52" ascii //weight: 1
        $x_1_4 = "/?r=site/GetController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


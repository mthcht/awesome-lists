rule Trojan_Win32_Fakevisec_149091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakevisec"
        threat_id = "149091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakevisec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "av_fake.scan.resources" ascii //weight: 1
        $x_1_2 = "You need to register Vista Security 2010" wide //weight: 1
        $x_1_3 = "You have 11 viruses!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


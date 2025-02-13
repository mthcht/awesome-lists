rule Trojan_Win32_Queresio_A_2147727038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Queresio.A"
        threat_id = "2147727038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Queresio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HOW DECRIPT FILES.hta" wide //weight: 10
        $x_10_2 = "sequre@tuta.io" wide //weight: 10
        $x_10_3 = "<title> HOW TO DECRYPT YOUR FILES</title>" wide //weight: 10
        $x_10_4 = "Your files are encrypted!</div>" wide //weight: 10
        $x_10_5 = "swapfile.sys" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


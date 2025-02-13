rule Trojan_Win64_Gooxer_A_2147825969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gooxer.A!dha"
        threat_id = "2147825969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gooxer"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.XorDecodeStr" ascii //weight: 1
        $x_1_2 = "main.AesEncrypt" ascii //weight: 1
        $x_1_3 = "main.MWork" ascii //weight: 1
        $x_1_4 = "main._cgoexpwrap" ascii //weight: 1
        $x_1_5 = "main.G_host" ascii //weight: 1
        $x_1_6 = "expand 32-byte kexpand 32-byte k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


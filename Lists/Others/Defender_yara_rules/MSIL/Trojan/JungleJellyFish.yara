rule Trojan_MSIL_JungleJellyFish_A_2147964581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/JungleJellyFish.A"
        threat_id = "2147964581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JungleJellyFish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "FastZip" ascii //weight: 5
        $x_5_2 = "ExtractZip" ascii //weight: 5
        $x_1_3 = "out.exe" ascii //weight: 1
        $x_1_4 = "dl.zip" ascii //weight: 1
        $x_5_5 = "SOFTWARE\\Microsoft\\Cryptography" ascii //weight: 5
        $x_5_6 = "MachineGuid" ascii //weight: 5
        $x_5_7 = "WebView2" ascii //weight: 5
        $x_5_8 = "premiumlicensecheck.com" ascii //weight: 5
        $x_1_9 = "open.usermanualvault.com" ascii //weight: 1
        $x_5_10 = {03 04 14 6f 0c 00 73 ?? ?? ?? ?? 25 05 6f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_5_*))) or
            (all of ($x*))
        )
}


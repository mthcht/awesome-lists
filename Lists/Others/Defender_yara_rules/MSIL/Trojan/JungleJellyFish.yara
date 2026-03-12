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
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FastZip" ascii //weight: 1
        $x_1_2 = "ExtractZip" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Cryptography" ascii //weight: 1
        $x_1_4 = "MachineGuid" ascii //weight: 1
        $x_1_5 = "WebView2" ascii //weight: 1
        $x_1_6 = "premiumlicensecheck.com" ascii //weight: 1
        $x_1_7 = {03 04 14 6f 0c 00 73 ?? ?? ?? ?? 25 05 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


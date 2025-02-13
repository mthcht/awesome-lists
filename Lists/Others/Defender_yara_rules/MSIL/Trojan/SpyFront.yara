rule Trojan_MSIL_SpyFront_A_2147745548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyFront.A!MSR"
        threat_id = "2147745548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyFront"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "jomacoqui@gmail.com" wide //weight: 5
        $x_5_2 = "cmd /c taskkill /f /im chrome.exe" wide //weight: 5
        $x_1_3 = "ScreenBooking.exe" wide //weight: 1
        $x_1_4 = "Revenge@2.0.exe" wide //weight: 1
        $x_1_5 = "SendBlaster" ascii //weight: 1
        $x_1_6 = "Revenge@2.0.pdb" ascii //weight: 1
        $x_1_7 = "ScreenBookingFINAL.exe" wide //weight: 1
        $x_5_8 = "capturaTela.My" ascii //weight: 5
        $x_10_9 = {0c 17 0d 72 ?? ?? ?? ?? 13 04 02 28 ?? ?? ?? ?? 13 05 17 13 06 2b 49 09 08 fe 01 13 07 11 07 2c 02 17 0d 03 09 17 28 2f 00 00 0a 28 30 00 00 0a 0b 11 04 02 11 06 17 28 2f 00 00 0a 28 30 00 00 0a 07 08 d8 da 28 31 00 00 0a 28 32 00 00 0a 28 33 00 00 0a 13 04 09 17 d6 0d 11 06 17 d6 13 06 11 06 11 05 31 b1 28 34 00 00 0a 11 04 28 ?? ?? ?? ?? 16 11 04 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}


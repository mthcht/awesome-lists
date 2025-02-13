rule TrojanDownloader_Win32_Sheloraki_A_2147653637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sheloraki.A"
        threat_id = "2147653637"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sheloraki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "291CF20557B281A9928FA360FF44D54DFB3DE4" wide //weight: 2
        $x_2_2 = "E2E6DB052DA54C543C587AE634289F53649575" wide //weight: 2
        $x_2_3 = "D77CC95E2AD3023DC11A4E88C7C120A63BA629" wide //weight: 2
        $x_2_4 = "2D2BC4B946E302200C6CD445F7030B04061830" wide //weight: 2
        $x_2_5 = "BC54BF51B399B195AEB191DE6BC793A3BF9" wide //weight: 2
        $x_2_6 = "4663379187840B42D9112917539446AA256" wide //weight: 2
        $x_1_7 = "EA68A969AE" ascii //weight: 1
        $x_1_8 = "213ED05AB1" ascii //weight: 1
        $x_1_9 = "DD48ED59EF39" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            (all of ($x*))
        )
}


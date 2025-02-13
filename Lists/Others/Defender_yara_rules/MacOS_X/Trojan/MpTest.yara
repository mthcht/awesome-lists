rule Trojan_MacOS_X_MpTest_A_2147646933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS_X/MpTest.A"
        threat_id = "2147646933"
        type = "Trojan"
        platform = "MacOS_X: "
        family = "MpTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "68c139d9-9dd3-47d2-a2c3-0b5ef63541a0" ascii //weight: 1
        $x_1_2 = "90bd28a3-433f-498a-b47f-36b4727925e9" ascii //weight: 1
        $x_1_3 = "39c39098-3a7f-43b0-9206-075c66111560" ascii //weight: 1
        $x_1_4 = "41304db6-370b-4a21-9972-6bb297b2ff5d" ascii //weight: 1
        $x_1_5 = "dd8b00e9-af86-4617-8e5e-397c242d98b0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


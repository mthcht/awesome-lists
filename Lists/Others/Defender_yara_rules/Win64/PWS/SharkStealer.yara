rule PWS_Win64_SharkStealer_A_2147956537_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/SharkStealer.A"
        threat_id = "2147956537"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "SharkStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.startpolling" ascii //weight: 1
        $x_1_2 = "main.fetchanddecrypt" ascii //weight: 1
        $x_1_3 = "main.detectcoin" ascii //weight: 1
        $x_1_4 = "main.blyadd_get." ascii //weight: 1
        $x_1_5 = "0xc2c25784E78AeE4C2Cb16d40358632Ed27eea" ascii //weight: 1
        $x_1_6 = "data-seed-prebsc-2-s1.binance.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win64_SharkStealer_B_2147956538_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/SharkStealer.B"
        threat_id = "2147956538"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "SharkStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3a 73 68 61 72 6b 5f [0-6] 3a}  //weight: 2, accuracy: Low
        $x_1_2 = "blyadget:" ascii //weight: 1
        $x_1_3 = "ext.zip" ascii //weight: 1
        $x_1_4 = "eth_call" ascii //weight: 1
        $x_1_5 = "connectToServer" ascii //weight: 1
        $x_1_6 = {83 fa 05 75 ?? 81 39 68 74 74 70 75 ?? 80 79 04 73 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


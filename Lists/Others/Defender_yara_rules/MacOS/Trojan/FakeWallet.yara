rule Trojan_MacOS_FakeWallet_AMTB_2147961711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FakeWallet!AMTB"
        threat_id = "2147961711"
        type = "Trojan"
        platform = "MacOS: "
        family = "FakeWallet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "5190ef1733183a0dc63fb623357f56d6" ascii //weight: 2
        $x_1_2 = "Quit Trezor Suite" ascii //weight: 1
        $x_1_3 = "Hide Trezor Suite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


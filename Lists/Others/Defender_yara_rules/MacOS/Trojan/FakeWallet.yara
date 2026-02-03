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

rule Trojan_MacOS_FakeWallet_A_2147962237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FakeWallet.A!MTB"
        threat_id = "2147962237"
        type = "Trojan"
        platform = "MacOS: "
        family = "FakeWallet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc 6f be a9 fd 7b 01 a9 fd 43 00 91 ff c3 0b d1 e8 03 01 aa e1 03 02 aa a0 83 12 f8 a8 03 12 f8 a0 a3 03 d1 e0 ab 00 f9 08 00 80 d2 e8 af 00 f9 bf 83 11 f8 93 03 00 94 20 00 00 90 00 a0 00 91 28 00 00 90 08 0d 40 f9 00 01 3f d6 a8 c3 03 d1 e8 a7 00 f9 a0 03 11 f8}  //weight: 1, accuracy: High
        $x_1_2 = {a8 e3 03 d1 e8 a3 00 f9 a0 83 10 f8 48 00 00 90 00 4d 44 f9 74 03 00 94 e1 77 40 f9 ce 03 00 94 a8 03 04 d1 e8 9f 00 f9 a0 03 10 f8 48 00 00 90 00 51 44 f9 6c 03 00 94 e1 77 40 f9 00 e4 00 2f e0 1b 00 fd a0 83 18 fc a0 03 18 fc 08 00 d1 d2 68 12 e8 f2 00 01 67 9e e0 3b 00 fd a0 83 17 fc 08 00 c7 d2 08 11 e8 f2 00 01 67 9e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


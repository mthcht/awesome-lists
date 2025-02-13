rule Trojan_Win32_Tarcloin_C_2147679018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarcloin.C"
        threat_id = "2147679018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarcloin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "407750728079708890421054704210525046405660623051309290408058105270473049405750512048210851079094" ascii //weight: 1
        $x_1_2 = "61102118412061182060704010465107410151109107509630951104310710454103310811083044910541012121703971053101611880714109505661285099108461129044411850673113" ascii //weight: 1
        $x_1_3 = "1122902581206117710481161114502920602093911430311116311111074038105720369095511171095107505310464051" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tarcloin_F_2147682165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarcloin.F"
        threat_id = "2147682165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarcloin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 07 2c 46 c0 e3 04 34 07 02 d8 88 5c 24}  //weight: 2, accuracy: High
        $x_1_2 = {68 75 6d 65 78 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_3 = "/658350965/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarcloin_G_2147682195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarcloin.G"
        threat_id = "2147682195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarcloin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7c 98 8a 4c 24 18 c0 e1 04 02 4c 24 1c 32 4c 24 17 88 4c 24 20 33 c0 8a 44 24 20 04 14 34 5a c0 c8 04}  //weight: 2, accuracy: High
        $x_1_2 = {3c 77 61 6c 6c 65 74 3e 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 69 62 63 75 72 6c 2e 64 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tarcloin_J_2147688081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarcloin.J"
        threat_id = "2147688081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarcloin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "user\":\"pioner.1" wide //weight: 1
        $x_1_2 = "Keyboard Inf." wide //weight: 1
        $x_1_3 = "IMG_61846_359718.jpg" wide //weight: 1
        $x_1_4 = {63 00 6f 00 64 00 65 00 4e 00 61 00 6d 00 65 00 3c 00 70 00 61 00 69 00 72 00 3e 00 3e 00 [0-16] 5f 00 62 00 66 00 67 00 [0-4] 3c 00 73 00 65 00 74 00 3e 00 24 00 73 00 65 00 63 00 73 00 49 00 64 00 6c 00 65 00 3c 00 70 00 61 00 69 00 72 00 3e 00 36 00 30 00 3c 00 73 00 65 00 74 00 3e 00 24 00 6d 00 69 00 6e 00 56 00 69 00 73 00 69 00 62 00 6c 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tarcloin_K_2147689919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarcloin.K"
        threat_id = "2147689919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarcloin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Global\\NwYnRZmRug-rIRixIV6H8-LBoqeBfkje-GWP1v28D7s" wide //weight: 2
        $x_1_2 = "pools\":[{\"url\":\"stratum+tcp://stratum.give-me-ltc.com:3333" wide //weight: 1
        $x_1_3 = {23 00 62 00 65 00 67 00 23 00 00 00 30 00 30 00 31 00 31 00 30 00 30 00}  //weight: 1, accuracy: High
        $x_1_4 = "bsplayer.exe|gom.exe|wmplayer.exe|Wimpy FLV Player.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


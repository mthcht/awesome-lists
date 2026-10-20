rule Trojan_MacOS_FakeWeb_DA_2147980608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FakeWeb.DA!MTB"
        threat_id = "2147980608"
        type = "Trojan"
        platform = "MacOS: "
        family = "FakeWeb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 57 3d 7c b1 a8 3b ec a2 1f dd 55 46 62 a6 8e 75 bd 00 81 94 7b 84 28 ff ed f6 6d 92 0e 35 2b e8 f4 f9 4d 48 b7 1e ea 68 55 d0 93 e3 76 70 f1 f2 ab 1f e2 c5 11 dd 0d 91 85 be f0 3e d1 38 db 31 2c 72 7c 7a e1 82 c5 4c 3e 73 9f 07 58 cf 88 79 36 51}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


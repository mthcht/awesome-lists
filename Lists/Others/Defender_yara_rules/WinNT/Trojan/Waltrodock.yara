rule Trojan_WinNT_Waltrodock_A_2147656151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Waltrodock.A"
        threat_id = "2147656151"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Waltrodock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 94 b8 90 90 90 90 8b 7d 98 8b d1 c1 e9 02 f3 ab 8b ca}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 dc e9 80 65 dd 00 80 65 de 00 80 65 df 00 80 65 e0 00 83 65 fc 00 8b 4d 08 89 4d d8 66 81 39 4d 5a}  //weight: 1, accuracy: High
        $x_1_3 = {ff d6 84 c0 0f 84 ?? ?? 00 00 83 c3 30 85 db 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Waltrodock_B_2147658069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Waltrodock.B"
        threat_id = "2147658069"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Waltrodock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ObReferenceObjectByHandle" ascii //weight: 1
        $x_1_2 = {75 1a 8b 4d 0c be 34 00 00 c0 32 d2 89 71 18 89 79 1c ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Waltrodock_C_2147658612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Waltrodock.C"
        threat_id = "2147658612"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Waltrodock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 d4 63 c6 45 d5 00 c6 45 d6 61 c6 45 d7 00 c6 45 d8 72 c6 45 d9 00 c6 45 da 64 c6 45 db 00 c6 45 dc 63 c6 45 dd 00 c6 45 de 74 c6 45 df 00 c6 45 e0 72 c6 45 e1 00 c6 45 e2 6c}  //weight: 1, accuracy: High
        $x_1_2 = "MsUsbIo" wide //weight: 1
        $x_1_3 = "usbinckey.sys" wide //weight: 1
        $x_1_4 = {53 50 59 44 4f 57 7e 31 5c [0-22] 5c 6f 62 6a 63 68 6b 5c 69 33 38 36 5c 52 6b 74 50 72 6f 74 65 63 74 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_5 = "cardctrl.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


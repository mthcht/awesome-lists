rule Trojan_Win64_CredStealer_LR_2147978158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CredStealer.LR!MTB"
        threat_id = "2147978158"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CredStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "78"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[1] Dropper basladi" ascii //weight: 1
        $x_2_2 = "[2] Anahtar okundu" ascii //weight: 2
        $x_3_3 = "[3] Payload okundu:" ascii //weight: 3
        $x_4_4 = "[4] EXE cozuldu:" ascii //weight: 4
        $x_5_5 = "[5] Yaziliyor:" ascii //weight: 5
        $x_6_6 = "[6] Calistiriliyor..." ascii //weight: 6
        $x_7_7 = "[8] Temizleniyor..." ascii //weight: 7
        $x_8_8 = "[HATA] EXE cozulemedi" ascii //weight: 8
        $x_9_9 = "[HATA] Payload bos" ascii //weight: 9
        $x_10_10 = "[RES-5] Resource lock edildi" ascii //weight: 10
        $x_11_11 = "[RES-6] Resource okundu:" ascii //weight: 11
        $x_12_12 = "[RES-HATA] LockResource basarisiz" ascii //weight: 12
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


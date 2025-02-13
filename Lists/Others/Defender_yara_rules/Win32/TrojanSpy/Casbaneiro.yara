rule TrojanSpy_Win32_Casbaneiro_A_2147735899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Casbaneiro.A"
        threat_id = "2147735899"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Casbaneiro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\DeskCoringa\\Desktop\\to Coringa\\mORMot-master\\" ascii //weight: 10
        $x_10_2 = "E:\\Tops\\Componentes\\mORMot-master\\" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Casbaneiro_S_2147838833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Casbaneiro.S!MTB"
        threat_id = "2147838833"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Casbaneiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 55 68 c8 42 61 00 64 ff 30 64 89 20 8b 45 fc e8 be fc ff ff 33 c0 5a 59 59 64 89 10 eb 15 e9 9f 58 df ff 8b 55 fc 8b 45 fc e8 d0 00 00 00 e8 ab 5d df ff 8b 45 fc 80 b8 bc 00 00 00 00 74 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


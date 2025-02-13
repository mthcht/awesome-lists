rule Worm_Win32_Notube_A_2147617848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Notube.A"
        threat_id = "2147617848"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Notube"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e8 00 f4 00 f4 00 f0 00 ba 00 af 00 af 00 f7 00 f7 00 f7 00 ae 00 f9 00 ef 00 f5 00 f4 00 f5 00 e2 00 e5 00 ae 00 e3 00 ef 00 ed 00 af 00 f6 00 af 00 eb 00}  //weight: 10, accuracy: High
        $x_1_2 = "AD:\\baixa\\Project1.vbp" wide //weight: 1
        $x_1_3 = "Messenger\\msgsc.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}


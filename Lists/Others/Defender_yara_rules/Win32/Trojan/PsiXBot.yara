rule Trojan_Win32_PsiXBot_PA_2147746226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsiXBot.PA!MTB"
        threat_id = "2147746226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsiXBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {ff 31 5e 83 c1 04 f7 de 83 ee 2d 83 c6 fe 83 ee ff 29 de 29 db 01 f3 c7 42 00 00 00 00 00 31 32 8d 7f 04 8d 52 04 81 ff ?? ?? 00 00 75}  //weight: 20, accuracy: Low
        $x_1_2 = {aa cb fb ff 29 ?? 24 83 ec 04 [0-16] aa cb fb ff 29 ?? 24 83 ec 04 [0-16] aa cb fb ff 29 ?? 24 83 ec 04 [0-16] 00 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_Agenthao_J_2147743631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agenthao.J!ibt"
        threat_id = "2147743631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agenthao"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "www.tohao123.com" wide //weight: 1
        $x_1_2 = ".exe /autorun" wide //weight: 1
        $x_1_3 = "win32_logicaldisk.deviceid=\"C:\"" wide //weight: 1
        $x_1_4 = {02 28 06 00 00 06 6f 52 00 00 0a 28 53 00 00 0a 72 ?? 00 00 70 11 05 72 ?? 00 00 70 28 4d 00 00 0a 6f 54 00 00 0a 7d 0c 00 00 04 de 0d}  //weight: 1, accuracy: Low
        $x_1_5 = "timerFirefox_Tick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


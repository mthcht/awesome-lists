rule Backdoor_Win32_Potlonad_A_2147638862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Potlonad.A"
        threat_id = "2147638862"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Potlonad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bots.php?name=" ascii //weight: 1
        $x_1_2 = "PatoDonald($Fuego[1]);" ascii //weight: 1
        $x_1_3 = "$Fuego = @explode(\"BotJava\" , $MiCalificacion) ;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


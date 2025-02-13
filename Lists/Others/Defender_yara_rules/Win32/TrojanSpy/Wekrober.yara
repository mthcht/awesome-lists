rule TrojanSpy_Win32_Wekrober_G_2147691809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wekrober.G"
        threat_id = "2147691809"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wekrober"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 2e 4a 50 47 00}  //weight: 1, accuracy: High
        $x_1_2 = {2a 2e 54 58 54 00}  //weight: 1, accuracy: High
        $x_1_3 = {2a 2e 42 4d 50 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 6c 6f 71 75 65 61 64 6f 72 20 64 65 20 50 6f 70 2d 75 70 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "if exist \"%s\" goto 1" ascii //weight: 1
        $x_1_6 = "lidos ! -  Senha incorreta." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


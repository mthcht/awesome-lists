rule Trojan_Win32_Sohanad_MA_2147838928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sohanad.MA!MTB"
        threat_id = "2147838928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sohanad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {39 ce cd d6 6b 19 09 96 fb c1 56 23 6b 07 c0 a3 11 e2 3c f2 b5 82 f0 2c 52 c1 0f 82 a0 ee e5 0c}  //weight: 5, accuracy: High
        $x_5_2 = {83 68 c9 66 aa e3 23 c4 f1 e8 df ff 3e 14 08 70 df bd 1c d0 77 76 b3 97 e9 92 59 2e d1 b8 39 f2}  //weight: 5, accuracy: High
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
        $x_1_4 = "DeviceIoControl" ascii //weight: 1
        $x_1_5 = "LockServiceDatabase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


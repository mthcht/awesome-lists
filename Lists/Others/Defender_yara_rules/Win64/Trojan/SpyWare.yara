rule Trojan_Win64_SpyWare_AAA_2147972889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyWare.AAA!AMTB"
        threat_id = "2147972889"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyWare"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Desktop\\spyware\\client\\code\\obj\\Release\\net5.0-windows\\win-x64\\spyware.pdb" ascii //weight: 10
        $x_1_2 = "KeyloggerModule" ascii //weight: 1
        $x_1_3 = "KEYLOG:" wide //weight: 1
        $x_1_4 = "Erreur dans le keylogger:" wide //weight: 1
        $x_1_5 = "SpywareFramework" ascii //weight: 1
        $x_1_6 = "CaptureMicrophoneAudio" ascii //weight: 1
        $x_1_7 = "Microsoft\\Windows\\logs.txt" wide //weight: 1
        $x_1_8 = "spyware.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

